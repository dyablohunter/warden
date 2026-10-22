"""Log plumbing: one streaming journald reader fanned out to many consumers, a rotation-safe file
tailer, and an error-signature tracker that turns noisy error logs into "what is NEW" signals."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import threading
import time
from glob import glob

from warden.util import SAFE_ENV

log = logging.getLogger("warden.journal")

FIELDS = "MESSAGE,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,PRIORITY,_TRANSPORT,_PID"


def entry_from_json(line: str) -> dict | None:
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return None
    msg = e.get("MESSAGE")
    if isinstance(msg, list):  # non-UTF8 messages arrive as byte arrays
        msg = bytes(x for x in msg if isinstance(x, int)).decode("utf-8", "replace")
    try:
        prio = int(e.get("PRIORITY", 6))
    except (TypeError, ValueError):
        prio = 6
    return {
        "msg": msg or "",
        "ident": e.get("SYSLOG_IDENTIFIER") or "",
        "unit": e.get("_SYSTEMD_UNIT") or "",
        "prio": prio,
        "transport": e.get("_TRANSPORT") or "",
        "pid": e.get("_PID") or "",
        "ts": int(e.get("__REALTIME_TIMESTAMP", "0") or 0) / 1e6 or time.time(),
        "cursor": e.get("__CURSOR"),
    }


class JournalStream(threading.Thread):
    """`journalctl -f -o json` in a single long-lived process; resumes from the saved cursor."""

    def __init__(self, db, handlers: list, cursor_key: str = "cursor.journal"):
        super().__init__(name="journal", daemon=True)
        self.db, self.handlers, self.cursor_key = db, handlers, cursor_key
        self.stop_event = threading.Event()
        self.proc: subprocess.Popen | None = None
        self.lines = 0

    def stop(self) -> None:
        self.stop_event.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def run(self) -> None:
        backoff = 2
        while not self.stop_event.is_set():
            cursor = self.db.kv_get(self.cursor_key)
            args = ["journalctl", "-f", "-o", "json", "--no-pager", f"--output-fields={FIELDS}"]
            args += ["--after-cursor", cursor] if cursor else ["-n", "0"]
            try:
                self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=dict(SAFE_ENV), text=True, bufsize=1)
            except OSError as exc:
                log.error("cannot start journalctl: %s", exc)
                self.stop_event.wait(60)
                continue
            log.info("journal stream started (%s)", "resuming" if cursor else "from now")
            last_save = time.time()
            last_cursor = None
            for line in self.proc.stdout:
                e = entry_from_json(line)
                if not e:
                    continue
                last_cursor = e["cursor"] or last_cursor
                self.lines += 1
                for h in self.handlers:
                    try:
                        h(e)
                    except Exception:  # noqa: BLE001 — one bad handler must not stop the stream
                        log.exception("journal handler failed")
                if time.time() - last_save > 10 and last_cursor:
                    self.db.kv_set(self.cursor_key, last_cursor)
                    last_save = time.time()
                if self.stop_event.is_set():
                    break
            if last_cursor:
                self.db.kv_set(self.cursor_key, last_cursor)
            if not self.stop_event.is_set():
                log.warning("journal stream ended; restarting in %ss", backoff)
                self.stop_event.wait(backoff)
                backoff = min(60, backoff * 2)


class FileTailer:
    """Incremental reader for log files matched by globs; survives rotation and truncation."""

    def __init__(self, patterns: list[str], from_end: bool = True):
        self.patterns = patterns
        self.offsets: dict[str, tuple[int, int]] = {}
        if from_end:  # don't punish history on start
            for f in self.files():
                try:
                    st = os.stat(f)
                    self.offsets[f] = (st.st_ino, st.st_size)
                except OSError:
                    pass

    def files(self) -> list[str]:
        out: set[str] = set()
        for p in self.patterns:
            out.update(f for f in glob(p) if not f.endswith((".gz", ".xz", ".bz2", ".zst")) and not re.search(r"\.\d+$", f))
        return sorted(out)

    def read(self, max_bytes: int = 32 * 1024 * 1024):
        """Yield (path, line) for new complete lines."""
        for f in self.files():
            try:
                st = os.stat(f)
            except OSError:
                continue
            ino, off = self.offsets.get(f, (st.st_ino, 0))
            if ino != st.st_ino or st.st_size < off:
                off = 0
            if st.st_size == off:
                self.offsets[f] = (st.st_ino, off)
                continue
            try:
                with open(f, "rb") as fh:
                    fh.seek(off)
                    chunk = fh.read(min(st.st_size - off, max_bytes))
            except OSError:
                continue
            end = chunk.rfind(b"\n") + 1
            self.offsets[f] = (st.st_ino, off + end)
            for raw in chunk[:end].splitlines():
                yield f, raw.decode("utf-8", "replace")


# ── error signatures ───────────────────────────────────────────────────────
_NORM = [
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<hex>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b"), "<ip6>"),
    (re.compile(r"'[^']{24,}'|\"[^\"]{24,}\""), "<str>"),
    (re.compile(r"\d+"), "<n>"),
    (re.compile(r"\s+"), " "),
]


def normalize_message(msg: str) -> str:
    for rx, rep in _NORM:
        msg = rx.sub(rep, msg)
    return msg.strip()[:240]


def signature(ident: str, msg: str) -> tuple[str, str]:
    norm = normalize_message(msg)
    return hashlib.sha1(f"{ident}|{norm}".encode()).hexdigest()[:16], norm


class ErrorTracker:
    """Counts error-level journal messages by normalised signature; flushes to the DB periodically.

    Only *new* signatures wake the LLM (health_pulse gate), so a service that logs the same error
    10,000 times a day costs one review, not 10,000.
    """

    def __init__(self, db, skip_units: tuple[str, ...] = ("warden.service",)):
        self.db, self.skip_units = db, skip_units
        self.lock = threading.Lock()
        self.pending: dict[str, list] = {}

    def wants(self, e: dict) -> bool:
        if e["unit"] in self.skip_units:
            return False
        return e["prio"] <= 3 or (e["transport"] == "kernel" and e["prio"] <= 4)

    def add(self, e: dict) -> None:
        if not self.wants(e):
            return
        ident = e["ident"] or e["unit"] or "?"
        sig, norm = signature(ident, e["msg"])
        with self.lock:
            p = self.pending.get(sig)
            if p:
                p[3] += 1
                p[5] = e["ts"]
            else:
                self.pending[sig] = [ident, e["unit"], norm, 1, e["ts"], e["ts"], e["msg"][:400]]

    def flush(self) -> int:
        with self.lock:
            items, self.pending = self.pending, {}
        for sig, (ident, unit, norm, count, first, last, sample) in items.items():
            self.db.x(
                """INSERT INTO log_signatures(sig,ident,unit,normalized,sample,first_seen,last_seen,count) VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(sig) DO UPDATE SET count=count+excluded.count, last_seen=excluded.last_seen""",
                (sig, ident, unit, norm, sample, first, last, count),
            )
        return len(items)

    def seed(self, lines: list[str]) -> int:
        """Load historical errors (journalctl -o json output) as the known baseline."""
        for line in lines:
            e = entry_from_json(line)
            if e:
                self.add(e)
        return self.flush()
