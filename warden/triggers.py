"""Triggers: cheap deterministic watchers that wake the agent.

* metric  — read from the sentinel's shared /proc snapshot (no extra work per trigger)
* log     — pushed in real time from the journald stream, sliding-window count
* command / service / port / file — evaluated every `interval_s`
When a condition holds for `consecutive` evaluations and the trigger is out of `cooldown_s`, an event is
recorded (with the trigger's instructions) and the daemon wakes up.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import socket
import threading
import time
from collections import deque
from pathlib import Path

from warden import safety, util
from warden.config import SEVERITIES

log = logging.getLogger("warden.triggers")

KINDS = ("metric", "command", "log", "service", "port", "file")
METRICS = (
    # gauges
    "load1", "load_per_cpu", "mem_avail_pct", "swap_used_pct", "procs_total", "oom_kills", "failed_units",
    "disk_used_pct", "inode_used_pct", "disk_full_eta_h", "disk_busy_pct", "ro_mounts",
    "conn_total", "syn_recv", "port_conns", "conntrack_pct",
    # rates per second
    "net_rx_mbps", "net_tx_mbps", "net_rx_kpps", "net_rx_util_pct", "tcp_passive_opens_ps", "syncookies_sent_ps",
    "listen_drops_ps", "tcp_retrans_ps", "udp_in_ps", "udp_rcvbuf_errors_ps", "icmp_echo_ps",
    "http_req_ps", "http_4xx_ps", "http_5xx_ps",
)
OPS = (">", ">=", "<", "<=", "==", "!=", "increase")
FIRE_ON = ("exit_nonzero", "exit_zero", "match", "no_match", "numeric", "changed")
PRIORITIES = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}

MIN_INTERVAL = 15
MAX_TRIGGERS = 100


def compare(value: float, op: str, threshold: float, previous: float | None = None) -> bool:
    if op == ">":
        return value > threshold
    if op == ">=":
        return value >= threshold
    if op == "<":
        return value < threshold
    if op == "<=":
        return value <= threshold
    if op == "==":
        return value == threshold
    if op == "!=":
        return value != threshold
    if op == "increase":
        return previous is not None and value - previous > threshold
    raise ValueError(f"bad op {op}")


# ── validation ─────────────────────────────────────────────────────────────
def validate(t: dict) -> tuple[dict | None, str | None]:
    """Normalise a trigger definition coming from the agent/CLI. Returns (trigger, error)."""
    name = str(t.get("name", "")).strip()
    if not re.match(r"^[a-z0-9][a-z0-9_.-]{1,63}$", name):
        return None, "name must be 2-64 chars of [a-z0-9_.-]"
    kind = t.get("kind")
    if kind not in KINDS:
        return None, f"kind must be one of {KINDS}"
    spec = dict(t.get("spec") or {})
    sev = str(t.get("severity", "medium")).lower()
    if sev not in SEVERITIES:
        return None, f"severity must be one of {SEVERITIES}"
    try:
        out = {
            "name": name, "kind": kind, "severity": sev,
            "interval_s": max(MIN_INTERVAL, min(86400, int(t.get("interval_s", 60)))),
            "cooldown_s": max(60, min(7 * 86400, int(t.get("cooldown_s", 1800)))),
            "consecutive": max(1, min(100, int(t.get("consecutive", 1)))),
            "instructions": str(t.get("instructions", ""))[:2000],
            "enabled": 1 if t.get("enabled", True) else 0,
            "once": 1 if t.get("once", False) else 0,
            "expires_at": None,
            "incident_id": t.get("incident_id"),
        }
        if t.get("expires_in_minutes"):
            out["expires_at"] = time.time() + 60 * max(1, int(t["expires_in_minutes"]))
        elif t.get("expires_at"):
            out["expires_at"] = float(t["expires_at"])
    except (TypeError, ValueError) as exc:
        return None, f"bad numeric field: {exc}"

    if kind == "metric":
        if spec.get("metric") not in METRICS:
            return None, f"spec.metric must be one of {METRICS}"
        if spec.get("op", ">") not in OPS:
            return None, f"spec.op must be one of {OPS}"
        try:
            spec["value"] = float(spec.get("value"))
        except (TypeError, ValueError):
            return None, "spec.value must be a number"
        spec.setdefault("op", ">")
        if "path" in spec and "arg" not in spec:
            spec["arg"] = spec.pop("path")
        if spec.get("metric") == "port_conns" and not str(spec.get("arg", "")).isdigit():
            return None, "port_conns needs spec.arg = port number"
        if "arg" in spec:
            spec["arg"] = str(spec["arg"])
    elif kind == "command":
        cmd = str(spec.get("command", "")).strip()
        v = safety.is_read_only(cmd)
        if not v.allowed:
            return None, f"command triggers must be read-only: {v.reason}"
        fire_on = spec.get("fire_on", "exit_nonzero")
        if fire_on not in FIRE_ON:
            return None, f"spec.fire_on must be one of {FIRE_ON}"
        if fire_on in ("match", "no_match"):
            try:
                re.compile(spec.get("pattern", ""))
            except re.error as exc:
                return None, f"bad pattern: {exc}"
        if fire_on == "numeric":
            if spec.get("op", ">") not in OPS:
                return None, f"spec.op must be one of {OPS}"
            try:
                spec["value"] = float(spec.get("value"))
            except (TypeError, ValueError):
                return None, "spec.value must be a number"
            spec.setdefault("op", ">")
        spec["timeout"] = max(1, min(120, int(spec.get("timeout", 30))))
        spec["command"] = cmd
        spec["fire_on"] = fire_on
    elif kind == "log":
        if not spec.get("pattern"):
            return None, "spec.pattern is required"
        try:
            re.compile(spec["pattern"])
        except re.error as exc:
            return None, f"bad pattern: {exc}"
        for k in ("unit", "identifier"):
            if spec.get(k) and not re.match(r"^[\w@.:/-]+$", str(spec[k])):
                return None, f"spec.{k} has invalid characters"
        if spec.get("priority") and spec["priority"] not in PRIORITIES:
            return None, "spec.priority must be a syslog level name"
        spec["min_count"] = max(1, int(spec.get("min_count", 1)))
        spec["window_s"] = max(30, min(86400, int(spec.get("window_s", 300))))
    elif kind == "service":
        if not re.match(r"^[\w@.:-]+$", str(spec.get("unit", ""))):
            return None, "spec.unit is required"
    elif kind == "port":
        try:
            spec["port"] = int(spec["port"])
        except (KeyError, TypeError, ValueError):
            return None, "spec.port is required"
        spec.setdefault("host", "127.0.0.1")
        spec["timeout"] = max(1, min(30, int(spec.get("timeout", 5))))
    elif kind == "file":
        if not os.path.isabs(str(spec.get("path", ""))):
            return None, "spec.path must be absolute"
    out["spec"] = spec
    return out, None


# ── evaluation ─────────────────────────────────────────────────────────────
def _file_digest(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"error:{exc.__class__.__name__}"


def log_entry_matches(spec: dict, e: dict) -> bool:
    if spec.get("identifier") and e["ident"] != spec["identifier"]:
        return False
    if spec.get("unit"):
        u = spec["unit"]
        if e["unit"] != u and e["unit"] != f"{u}.service":
            return False
    if spec.get("priority") and e["prio"] > PRIORITIES[spec["priority"]]:
        return False
    return re.search(spec["pattern"], e["msg"]) is not None


def service_verdict(unit: str, show_output: str) -> tuple[bool, str, str]:
    """`systemctl show` output -> (fire, state, detail). Oneshot/timer-driven units are normally inactive: only failed counts."""
    props = dict(line.split("=", 1) for line in show_output.splitlines() if "=" in line)
    st = props.get("ActiveState") or "unknown"
    if props.get("LoadState") == "not-found":
        return True, "not-found", f"{unit} does not exist"
    if props.get("Type") == "oneshot":
        return st == "failed", st, f"{unit} (oneshot) is {st}"
    return st not in ("active", "reloading"), st, f"{unit} is {st}"


def evaluate(t: dict, sampler=None) -> tuple[bool, str, str, dict]:
    """Return (matched, value, detail, new_state) for polled kinds. Never raises for expected failures."""
    spec, state = t["spec"], dict(t.get("state") or {})
    kind = t["kind"]
    if kind == "metric":
        if sampler is None:
            from warden.metrics import Sampler

            sampler = Sampler()
            sampler.sample()
            time.sleep(1)
            sampler.sample()
        v, label = sampler.value(spec["metric"], spec.get("arg"))
        if v is None:
            return False, "n/a", f"{label}: no data (yet)", state
        prev = state.get("prev")
        state["prev"] = v
        hit = compare(v, spec["op"], spec["value"], prev)
        rel = f"increase>{spec['value']:g} from {prev:g}" if spec["op"] == "increase" and prev is not None else f"{spec['op']} {spec['value']:g}"
        return hit, f"{v:.2f}", f"{label} = {v:.2f} ({rel})", state
    if kind == "command":
        res = util.run(spec["command"], timeout=spec.get("timeout", 30))
        out = (res.stdout + res.stderr).strip()
        f = spec["fire_on"]
        if f == "exit_nonzero":
            hit = res.code != 0
        elif f == "exit_zero":
            hit = res.code == 0
        elif f == "match":
            hit = re.search(spec.get("pattern", ""), out, re.M) is not None
        elif f == "no_match":
            hit = re.search(spec.get("pattern", ""), out, re.M) is None
        elif f == "numeric":
            m = re.search(r"-?\d+(?:\.\d+)?", res.stdout)
            num = float(m.group(0)) if m else float("nan")
            prev = state.get("prev")
            state["prev"] = num
            hit = m is not None and compare(num, spec["op"], spec["value"], prev)
        else:  # changed
            digest = hashlib.sha256(res.stdout.encode()).hexdigest()
            prev = state.get("digest")
            state["digest"] = digest
            hit = prev is not None and prev != digest
        return hit, f"exit={res.code}", f"`{spec['command']}` exit={res.code}\n{util.truncate(out, 1500)}", state
    if kind == "log":  # used by test_trigger only; live log triggers are pushed from the journal stream
        parts = ["journalctl", "-q", "--no-pager", "-o", "short-iso", "--since", f"-{spec['window_s']}s"]
        if spec.get("unit"):
            parts += ["-u", spec["unit"]]
        if spec.get("identifier"):
            parts += ["-t", spec["identifier"]]
        if spec.get("priority"):
            parts += ["-p", spec["priority"]]
        res = util.run(parts, timeout=30)
        rx = re.compile(spec["pattern"])
        hits = [ln for ln in res.stdout.splitlines() if rx.search(ln)]
        return len(hits) >= spec["min_count"], str(len(hits)), f"{len(hits)} matching lines in last {spec['window_s']}s:\n{util.truncate(chr(10).join(hits[-8:]), 1500)}", state
    if kind == "service":
        res = util.run(["systemctl", "show", "-p", "ActiveState", "-p", "Type", "-p", "LoadState", spec["unit"]], timeout=15)
        return (*service_verdict(spec["unit"], res.stdout), state)
    if kind == "port":
        try:
            with socket.create_connection((spec["host"], spec["port"]), timeout=spec["timeout"]):
                return False, "open", f"{spec['host']}:{spec['port']} reachable", state
        except OSError as exc:
            return True, "closed", f"{spec['host']}:{spec['port']} unreachable: {exc}", state
    if kind == "file":
        digest = _file_digest(spec["path"])
        prev = state.get("digest")
        state["digest"] = digest
        hit = prev is not None and prev != digest
        return hit, digest[:16], f"{spec['path']} changed ({(prev or '')[:12]} -> {digest[:12]})", state
    raise ValueError(f"unknown kind {kind}")


class TriggerEngine:
    def __init__(self, db, on_fire=None, sampler=None):
        self.db = db
        self.on_fire = on_fire or (lambda: None)
        self.sampler = sampler
        self.lock = threading.RLock()
        self._log_triggers: list[dict] = []
        self._log_loaded = 0.0
        self.log_windows: dict[int, deque] = {}
        self.log_samples: dict[int, deque] = {}

    # ── firing (shared) ───────────────────────────────────────────────────
    def _fire(self, t: dict, detail: str, now: float, fields: dict, state: dict) -> bool:
        if t["last_fired"] and now - t["last_fired"] < t["cooldown_s"]:
            return False
        msg = f"Trigger '{t['name']}' ({t['kind']}) fired: {detail}"
        if t["instructions"]:
            msg += f"\nTrigger instructions: {t['instructions']}"
        if t["incident_id"]:
            msg += f"\nLinked incident: #{t['incident_id']}"
        self.db.add_event("trigger", f"trigger:{t['name']}", t["severity"], msg, trigger_id=t["id"])
        fields.update(last_fired=now, fire_count=t["fire_count"] + 1)
        state["active"] = True
        if t["once"]:
            fields["enabled"] = 0
        log.warning("TRIGGER %s: %s", t["name"], detail[:200])
        return True

    def _recover(self, t: dict, detail: str, now: float, state: dict) -> None:
        state["active"] = False
        self.db.add_event("trigger", f"trigger_recovered:{t['name']}", "info", f"Trigger '{t['name']}' recovered: {detail}", trigger_id=t["id"])
        if t["incident_id"]:
            self.db.incident_note(t["incident_id"], "trigger", f"trigger {t['name']} recovered: {detail}")
            self.db.incident_update(t["incident_id"], next_check=now)

    # ── polled kinds ──────────────────────────────────────────────────────
    def tick(self, now: float | None = None) -> int:
        now = now or time.time()
        fired = 0
        with self.lock:
            for t in self.db.triggers(enabled_only=True):
                if t["expires_at"] and t["expires_at"] < now:
                    self.db.trigger_set(t["id"], enabled=0)
                    self.db.add_event("trigger", f"trigger_expired:{t['name']}", "info", f"trigger {t['name']} expired and was disabled", trigger_id=t["id"])
                    continue
                if t["kind"] == "log":
                    fired += self._log_recovery(t, now)
                    continue
                if t["last_eval"] and now - t["last_eval"] < t["interval_s"]:
                    continue
                try:
                    hit, value, detail, state = evaluate(t, self.sampler)
                except Exception as exc:  # noqa: BLE001 — a broken trigger must not kill the sentinel
                    log.warning("trigger %s failed: %s", t["name"], exc)
                    self.db.trigger_set(t["id"], last_eval=now, last_value=f"error: {exc}"[:200])
                    continue
                streak = t["streak"] + 1 if hit else 0
                fields = {"last_eval": now, "last_value": value[:200], "streak": streak}
                if hit and streak >= t["consecutive"]:
                    fired += self._fire(t, detail, now, fields, state)
                elif not hit and state.get("active"):
                    self._recover(t, detail, now, state)
                    fired += bool(t["incident_id"])
                fields["state"] = state
                self.db.trigger_set(t["id"], **fields)
        if fired:
            self.on_fire()
        return fired

    # ── log kind (pushed from the journal stream) ─────────────────────────
    def _log_list(self) -> list[dict]:
        if time.time() - self._log_loaded > 30:
            self._log_triggers = [t for t in self.db.triggers(enabled_only=True) if t["kind"] == "log"]
            self._log_loaded = time.time()
        return self._log_triggers

    def reload(self) -> None:
        self._log_loaded = 0.0

    def on_journal(self, e: dict) -> None:
        fired = False
        for t in self._log_list():
            spec = t["spec"]
            try:
                if not log_entry_matches(spec, e):
                    continue
            except re.error:
                continue
            with self.lock:
                win = self.log_windows.setdefault(t["id"], deque())
                samples = self.log_samples.setdefault(t["id"], deque(maxlen=6))
                win.append(e["ts"])
                samples.append(f"[{e['ident'] or e['unit']}] {e['msg'][:300]}")
                while win and win[0] < e["ts"] - spec["window_s"]:
                    win.popleft()
                if len(win) >= spec["min_count"]:
                    cur = self.db.trigger(t["name"])  # fresh state for cooldown
                    if not cur or not cur["enabled"]:
                        continue
                    now = time.time()
                    fields, state = {"last_eval": now, "last_value": str(len(win))}, dict(cur["state"])
                    detail = f"{len(win)} matching log lines in {spec['window_s']}s:\n" + "\n".join(samples)
                    if self._fire(cur, detail, now, fields, state):
                        fired = True
                    fields["state"] = state
                    self.db.trigger_set(cur["id"], **fields)
                    self._log_triggers = [x if x["id"] != cur["id"] else {**cur, **fields} for x in self._log_triggers]
        if fired:
            self.on_fire()

    def _log_recovery(self, t: dict, now: float) -> int:
        win = self.log_windows.get(t["id"])
        if win is not None:
            while win and win[0] < now - t["spec"]["window_s"]:
                win.popleft()
        if t["state"].get("active") and (not win or len(win) < t["spec"]["min_count"]):
            state = dict(t["state"])
            self._recover(t, "no matching log lines in the window", now, state)
            self.db.trigger_set(t["id"], state=state)
            return 1 if t["incident_id"] else 0
        return 0


def default_triggers(settings) -> list[dict]:
    defs = [
        # disk
        dict(name="disk-full", kind="metric", severity="high", interval_s=60, cooldown_s=3600,
             spec={"metric": "disk_used_pct", "op": ">", "value": 90},
             instructions="A filesystem is over 90%. Find what is filling it (logs, journals, docker, apt cache, core dumps, uploads) and free space safely."),
        dict(name="disk-filling-fast", kind="metric", severity="high", interval_s=60, cooldown_s=3600, consecutive=3,
             spec={"metric": "disk_full_eta_h", "op": "<", "value": 6},
             instructions="At the current write rate a filesystem fills within 6h: runaway logs, log-flooding attack, upload abuse or a stuck job. Find the writer (iotop-free: `du`, `lsof +L1`, `find -mmin -30 -size +100M`)."),
        dict(name="inodes-full", kind="metric", severity="high", interval_s=300, cooldown_s=3600,
             spec={"metric": "inode_used_pct", "op": ">", "value": 90}),
        dict(name="disk-io-saturated", kind="metric", severity="medium", interval_s=15, cooldown_s=3600, consecutive=20,
             spec={"metric": "disk_busy_pct", "op": ">", "value": 95},
             instructions="A disk has been >95% busy for 5 minutes. Identify the I/O-heavy process; if it's a scheduled backup and expected, remember that."),
        dict(name="fs-readonly", kind="metric", severity="critical", interval_s=30, cooldown_s=3600,
             spec={"metric": "ro_mounts", "op": ">", "value": 0},
             instructions="A filesystem was remounted read-only (usually I/O errors or corruption). Check dmesg/journal -k and disk health."),
        dict(name="kernel-io-errors", kind="log", severity="high", cooldown_s=3600,
             spec={"identifier": "kernel", "pattern": r"I/O error|EXT4-fs error|XFS .*(?:error|corrupt)|nvme\S* .*(?:timeout|reset)|ata\d+.*failed command|Buffer I/O error", "min_count": 1, "window_s": 300},
             instructions="Kernel reports disk I/O errors: possible failing disk. Check SMART (smartctl -H) and plan replacement/backups."),
        # memory / cpu / processes
        dict(name="memory-low", kind="metric", severity="high", interval_s=30, cooldown_s=1800, consecutive=3,
             spec={"metric": "mem_avail_pct", "op": "<", "value": 5},
             instructions="Identify the memory hog; check for leaks or runaway processes; consider restarting the offending service."),
        dict(name="load-high", kind="metric", severity="medium", interval_s=60, cooldown_s=3600, consecutive=5,
             spec={"metric": "load_per_cpu", "op": ">", "value": 4},
             instructions="Check for runaway processes, crypto miners, fork storms or I/O wait."),
        dict(name="oom-kill", kind="metric", severity="high", interval_s=60, cooldown_s=1800,
             spec={"metric": "oom_kills", "op": "increase", "value": 0},
             instructions="The kernel OOM killer fired. Find what was killed and why."),
        dict(name="failed-units", kind="metric", severity="medium", interval_s=120, cooldown_s=21600,
             spec={"metric": "failed_units", "op": "increase", "value": 0},
             instructions="A systemd unit newly failed. Inspect it and fix or reset it."),
        # network / DoS
        dict(name="syn-flood", kind="metric", severity="high", interval_s=15, cooldown_s=900, consecutive=2,
             spec={"metric": "syncookies_sent_ps", "op": ">", "value": 5},
             instructions="The kernel is answering with SYN cookies: a SYN flood is in progress. Check SYN_RECV sources and nftables counters; tighten nft_syn_rate if needed."),
        dict(name="listen-overflow", kind="metric", severity="high", interval_s=15, cooldown_s=1800, consecutive=4,
             spec={"metric": "listen_drops_ps", "op": ">", "value": 1},
             instructions="Accept queues are overflowing: a service can't keep up (L7 flood, slowloris, or capacity). Find which port (port_conns, ss -ltn Recv-Q) and why."),
        dict(name="conntrack-full", kind="metric", severity="critical", interval_s=15, cooldown_s=1800,
             spec={"metric": "conntrack_pct", "op": ">", "value": 85},
             instructions="The connection-tracking table is nearly full; new connections will be dropped. Classic flood symptom: find the sources, consider raising nf_conntrack_max."),
        dict(name="uplink-saturated", kind="metric", severity="critical", interval_s=15, cooldown_s=1800, consecutive=3,
             spec={"metric": "net_rx_util_pct", "op": ">", "value": 85},
             instructions="Inbound bandwidth is near link capacity: a volumetric DDoS can't be fixed on the host. Tell the operator to enable upstream mitigation; ban the top sources meanwhile."),
        # integrity
        dict(name="passwd-changed", kind="file", severity="high", interval_s=60, cooldown_s=600,
             spec={"path": "/etc/passwd"}, instructions="Accounts changed: verify any new/modified user is legitimate (check audit log for Warden's own changes)."),
        dict(name="sudoers-changed", kind="file", severity="high", interval_s=60, cooldown_s=600, spec={"path": "/etc/sudoers"}),
        dict(name="root-authorized-keys-changed", kind="file", severity="high", interval_s=60, cooldown_s=600,
             spec={"path": "/root/.ssh/authorized_keys"}, instructions="Root SSH keys changed: verify every key is expected."),
        dict(name="ld-preload-changed", kind="file", severity="critical", interval_s=60, cooldown_s=600,
             spec={"path": "/etc/ld.so.preload"}, instructions="ld.so.preload is a classic rootkit persistence vector. Investigate immediately."),
        dict(name="reboot-required", kind="file", severity="low", interval_s=600, cooldown_s=86400,
             spec={"path": "/var/run/reboot-required"}, instructions="Updates require a reboot. Tell the operator (you may not reboot unless allowed)."),
    ]
    if Path("/usr/sbin/sshd").exists():
        defs.append(dict(name="sshd-config-changed", kind="file", severity="medium", interval_s=60, cooldown_s=600,
                         spec={"path": "/etc/ssh/sshd_config"}))
        defs.append(dict(name="ssh-down", kind="command", severity="critical", interval_s=60, cooldown_s=900, consecutive=2,
                         spec={"command": "systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket", "fire_on": "exit_nonzero"},
                         instructions="SSH is not running: restore remote access as top priority."))
    return defs
