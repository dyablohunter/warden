"""SQLite persistence. One connection shared across threads behind a lock."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from warden.util import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS routines (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  interval_minutes INTEGER NOT NULL,
  instructions TEXT NOT NULL DEFAULT '',
  collectors TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1,
  builtin INTEGER NOT NULL DEFAULT 0,
  protected INTEGER NOT NULL DEFAULT 0,
  gated INTEGER NOT NULL DEFAULT 1,
  suppress TEXT NOT NULL DEFAULT '[]',
  last_run REAL, next_run REAL,
  last_status TEXT, last_summary TEXT,
  last_outputs TEXT NOT NULL DEFAULT '{}',
  updated_at REAL, updated_by TEXT
);
CREATE TABLE IF NOT EXISTS triggers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  kind TEXT NOT NULL,
  spec TEXT NOT NULL DEFAULT '{}',
  severity TEXT NOT NULL DEFAULT 'medium',
  interval_s INTEGER NOT NULL DEFAULT 60,
  cooldown_s INTEGER NOT NULL DEFAULT 1800,
  consecutive INTEGER NOT NULL DEFAULT 1,
  instructions TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  builtin INTEGER NOT NULL DEFAULT 0,
  once INTEGER NOT NULL DEFAULT 0,
  expires_at REAL,
  incident_id INTEGER,
  last_eval REAL, last_fired REAL,
  streak INTEGER NOT NULL DEFAULT 0,
  fire_count INTEGER NOT NULL DEFAULT 0,
  last_value TEXT,
  state TEXT NOT NULL DEFAULT '{}',
  created_by TEXT, created_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  details TEXT NOT NULL DEFAULT '',
  created REAL, updated REAL, next_check REAL,
  checks INTEGER NOT NULL DEFAULT 0,
  resolution TEXT
);
CREATE TABLE IF NOT EXISTS incident_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL,
  ts REAL, author TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, source TEXT, kind TEXT, severity TEXT,
  ip TEXT, details TEXT,
  trigger_id INTEGER,
  processed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_unprocessed ON events(processed, ts);
CREATE TABLE IF NOT EXISTS bans (
  ip TEXT PRIMARY KEY,
  reason TEXT, source TEXT,
  created REAL, expires REAL,
  count INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS trusted_ips (
  ip TEXT PRIMARY KEY, user TEXT, last_seen REAL
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, run_id INTEGER, actor TEXT, tool TEXT,
  args TEXT, result TEXT, ok INTEGER
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started REAL, finished REAL,
  kind TEXT, name TEXT,
  status TEXT, severity TEXT, summary TEXT,
  steps INTEGER, tokens_in INTEGER, tokens_out INTEGER, tokens_cached INTEGER DEFAULT 0, error TEXT
);
CREATE TABLE IF NOT EXISTS log_signatures (
  sig TEXT PRIMARY KEY, ident TEXT, unit TEXT, normalized TEXT, sample TEXT,
  first_seen REAL, last_seen REAL, count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS log_signatures_first ON log_signatures(first_seen);
CREATE TABLE IF NOT EXISTS memory (
  key TEXT PRIMARY KEY, value TEXT, updated REAL
);
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY, value TEXT
);
CREATE TABLE IF NOT EXISTS emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, subject TEXT, severity TEXT, body TEXT,
  sent INTEGER NOT NULL DEFAULT 0, error TEXT
);
"""


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            if self.path != ":memory:":
                self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")  # only effective on new databases
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=30000")
            self.conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after a database was created."""
        wanted = {
            "routines": [("gated", "INTEGER NOT NULL DEFAULT 1"), ("suppress", "TEXT NOT NULL DEFAULT '[]'")],
            "runs": [("tokens_cached", "INTEGER DEFAULT 0")],
            "bans": [("edge_rule", "TEXT")],
        }
        for table, cols in wanted.items():
            have = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for name, ddl in cols:
                if name not in have:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    # ── low level ──────────────────────────────────────────────────────────
    def q(self, sql: str, args: tuple | list = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, args: tuple | list = ()) -> dict | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple | list = ()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.lastrowid or cur.rowcount

    # ── kv / memory ────────────────────────────────────────────────────────
    def kv_get(self, key: str, default: str | None = None) -> str | None:
        r = self.one("SELECT value FROM kv WHERE key=?", (key,))
        return r["value"] if r else default

    def kv_set(self, key: str, value: str) -> None:
        self.x("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def kv_prefix(self, prefix: str) -> dict[str, str]:
        return {r["key"][len(prefix):]: r["value"] for r in self.q("SELECT key,value FROM kv WHERE key LIKE ?", (prefix + "%",))}

    def memory_all(self) -> list[dict]:
        return self.q("SELECT key,value,updated FROM memory ORDER BY key")

    def memory_set(self, key: str, value: str) -> None:
        self.x(
            "INSERT INTO memory(key,value,updated) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
            (key, value, now()),
        )

    def memory_del(self, key: str) -> int:
        return self.x("DELETE FROM memory WHERE key=?", (key,))

    # ── audit / runs ───────────────────────────────────────────────────────
    def audit(self, run_id: int | None, actor: str, tool: str, args: dict, result: str, ok: bool) -> None:
        self.x(
            "INSERT INTO actions(ts,run_id,actor,tool,args,result,ok) VALUES(?,?,?,?,?,?,?)",
            (now(), run_id, actor, tool, json.dumps(args, default=str)[:4000], (result or "")[:4000], int(ok)),
        )

    def run_start(self, kind: str, name: str) -> int:
        return self.x("INSERT INTO runs(started,kind,name,status) VALUES(?,?,?,'running')", (now(), kind, name))

    def run_finish(self, run_id: int, **f: Any) -> None:
        f["finished"] = now()
        cols = ",".join(f"{k}=?" for k in f)
        self.x(f"UPDATE runs SET {cols} WHERE id=?", (*f.values(), run_id))

    # ── events ─────────────────────────────────────────────────────────────
    def add_event(self, source: str, kind: str, severity: str, details: str, ip: str | None = None, trigger_id: int | None = None) -> int:
        return self.x(
            "INSERT INTO events(ts,source,kind,severity,ip,details,trigger_id) VALUES(?,?,?,?,?,?,?)",
            (now(), source, kind, severity, ip, details[:4000], trigger_id),
        )

    def pending_events(self, limit: int = 5000) -> list[dict]:
        return self.q("SELECT * FROM events WHERE processed=0 ORDER BY ts LIMIT ?", (limit,))

    def mark_events(self, ids: list[int]) -> None:
        with self.lock:
            self.conn.executemany("UPDATE events SET processed=1 WHERE id=?", [(i,) for i in ids])

    # ── incidents ──────────────────────────────────────────────────────────
    def incident_open(self, title: str, severity: str, details: str, next_check: float) -> int:
        t = now()
        return self.x(
            "INSERT INTO incidents(title,severity,status,details,created,updated,next_check) VALUES(?,?,'open',?,?,?,?)",
            (title, severity, details, t, t, next_check),
        )

    def incident_note(self, incident_id: int, author: str, note: str) -> None:
        self.x("INSERT INTO incident_notes(incident_id,ts,author,note) VALUES(?,?,?,?)", (incident_id, now(), author, note[:8000]))
        self.x("UPDATE incidents SET updated=? WHERE id=?", (now(), incident_id))

    def incident(self, incident_id: int) -> dict | None:
        return self.one("SELECT * FROM incidents WHERE id=?", (incident_id,))

    def incident_notes(self, incident_id: int, limit: int = 40) -> list[dict]:
        rows = self.q("SELECT * FROM incident_notes WHERE incident_id=? ORDER BY id DESC LIMIT ?", (incident_id, limit))
        return list(reversed(rows))

    def incidents_active(self) -> list[dict]:
        return self.q("SELECT * FROM incidents WHERE status IN ('open','monitoring','needs_human') ORDER BY id")

    def incident_update(self, incident_id: int, **f: Any) -> None:
        f["updated"] = now()
        cols = ",".join(f"{k}=?" for k in f)
        self.x(f"UPDATE incidents SET {cols} WHERE id=?", (*f.values(), incident_id))

    # ── bans / trusted ─────────────────────────────────────────────────────
    def ban_get(self, ip: str) -> dict | None:
        return self.one("SELECT * FROM bans WHERE ip=?", (ip,))

    def ban_upsert(self, ip: str, reason: str, source: str, expires: float) -> None:
        self.x(
            """INSERT INTO bans(ip,reason,source,created,expires,count,active) VALUES(?,?,?,?,?,1,1)
               ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, source=excluded.source,
               created=excluded.created, expires=excluded.expires, count=bans.count+1, active=1""",
            (ip, reason, source, now(), expires),
        )

    def ban_deactivate(self, ip: str) -> int:
        return self.x("UPDATE bans SET active=0 WHERE ip=?", (ip,))

    def bans_active(self) -> list[dict]:
        self.x("UPDATE bans SET active=0 WHERE active=1 AND expires<?", (now(),))
        return self.q("SELECT * FROM bans WHERE active=1 ORDER BY created DESC")

    def trusted_add(self, ip: str, user: str) -> None:
        self.x(
            "INSERT INTO trusted_ips(ip,user,last_seen) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET user=excluded.user, last_seen=excluded.last_seen",
            (ip, user, now()),
        )

    def trusted_ips(self, max_age_s: float) -> set[str]:
        return {r["ip"] for r in self.q("SELECT ip FROM trusted_ips WHERE last_seen>?", (now() - max_age_s,))}

    # ── routines ───────────────────────────────────────────────────────────
    @staticmethod
    def _routine(r: dict) -> dict:
        r["collectors"] = json.loads(r["collectors"] or "[]")
        r["suppress"] = json.loads(r.get("suppress") or "[]")
        r["last_outputs"] = json.loads(r.get("last_outputs") or "{}")
        return r

    def routines(self, enabled_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM routines" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY interval_minutes, name"
        return [self._routine(r) for r in self.q(sql)]

    def routine(self, name: str) -> dict | None:
        r = self.one("SELECT * FROM routines WHERE name=?", (name,))
        return self._routine(r) if r else None

    def routine_upsert(self, r: dict, by: str) -> None:
        self.x(
            """INSERT INTO routines(name,description,interval_minutes,instructions,collectors,enabled,builtin,protected,gated,suppress,next_run,updated_at,updated_by)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET description=excluded.description, interval_minutes=excluded.interval_minutes,
               instructions=excluded.instructions, collectors=excluded.collectors, enabled=excluded.enabled,
               gated=excluded.gated, suppress=excluded.suppress, updated_at=excluded.updated_at, updated_by=excluded.updated_by""",
            (
                r["name"], r.get("description", ""), int(r["interval_minutes"]), r.get("instructions", ""),
                json.dumps(r.get("collectors", [])), int(r.get("enabled", 1)), int(r.get("builtin", 0)),
                int(r.get("protected", 0)), int(r.get("gated", 1)), json.dumps(r.get("suppress", [])), r.get("next_run"), now(), by,
            ),
        )

    def routine_set(self, name: str, **f: Any) -> None:
        for k in ("last_outputs", "suppress", "collectors"):
            if k in f and not isinstance(f[k], str):
                f[k] = json.dumps(f[k])
        cols = ",".join(f"{k}=?" for k in f)
        self.x(f"UPDATE routines SET {cols} WHERE name=?", (*f.values(), name))

    def routine_delete(self, name: str) -> int:
        return self.x("DELETE FROM routines WHERE name=?", (name,))

    # ── triggers ───────────────────────────────────────────────────────────
    @staticmethod
    def _trig(r: dict) -> dict:
        r["spec"] = json.loads(r["spec"] or "{}")
        r["state"] = json.loads(r["state"] or "{}")
        return r

    def triggers(self, enabled_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM triggers" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY id"
        return [self._trig(r) for r in self.q(sql)]

    def trigger(self, name: str) -> dict | None:
        r = self.one("SELECT * FROM triggers WHERE name=?", (name,))
        return self._trig(r) if r else None

    def trigger_upsert(self, t: dict, by: str) -> None:
        ts = now()
        self.x(
            """INSERT INTO triggers(name,kind,spec,severity,interval_s,cooldown_s,consecutive,instructions,enabled,builtin,once,expires_at,incident_id,created_by,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, spec=excluded.spec, severity=excluded.severity,
               interval_s=excluded.interval_s, cooldown_s=excluded.cooldown_s, consecutive=excluded.consecutive,
               instructions=excluded.instructions, enabled=excluded.enabled, once=excluded.once,
               expires_at=excluded.expires_at, incident_id=excluded.incident_id, updated_at=excluded.updated_at,
               streak=0, state='{}'""",
            (
                t["name"], t["kind"], json.dumps(t.get("spec", {})), t.get("severity", "medium"),
                int(t.get("interval_s", 60)), int(t.get("cooldown_s", 1800)), int(t.get("consecutive", 1)),
                t.get("instructions", ""), int(t.get("enabled", 1)), int(t.get("builtin", 0)), int(t.get("once", 0)),
                t.get("expires_at"), t.get("incident_id"), by, ts, ts,
            ),
        )

    def trigger_set(self, trigger_id: int, **f: Any) -> None:
        if "state" in f and not isinstance(f["state"], str):
            f["state"] = json.dumps(f["state"])
        cols = ",".join(f"{k}=?" for k in f)
        self.x(f"UPDATE triggers SET {cols} WHERE id=?", (*f.values(), trigger_id))

    def trigger_delete(self, name: str) -> int:
        return self.x("DELETE FROM triggers WHERE name=?", (name,))

    # ── emails ─────────────────────────────────────────────────────────────
    def emails_sent_since(self, ts: float) -> int:
        r = self.one("SELECT COUNT(*) AS n FROM emails WHERE sent=1 AND ts>?", (ts,))
        return r["n"] if r else 0

    def email_log(self, subject: str, severity: str, body: str, sent: bool, error: str | None = None) -> int:
        return self.x(
            "INSERT INTO emails(ts,subject,severity,body,sent,error) VALUES(?,?,?,?,?,?)",
            (now(), subject, severity, body[:20000], int(sent), error),
        )

    def emails_queued(self) -> list[dict]:
        return self.q("SELECT * FROM emails WHERE sent=0 AND error='queued' ORDER BY id")

    def emails_mark(self, ids: list[int], error: str | None) -> None:
        with self.lock:
            self.conn.executemany("UPDATE emails SET error=? WHERE id=?", [(error, i) for i in ids])

    # ── housekeeping ───────────────────────────────────────────────────────
    # retention (days) and hard row caps: storage stays bounded even under a sustained attack
    RETENTION = {"events_info": 7, "events": 30, "emails": 30, "signatures_unseen": 30, "triggers_disabled": 30,
                 "bans_inactive": 90, "incidents_resolved": 180, "trusted_ips": 365}
    ROW_CAPS = {"events": 100_000, "actions": 50_000, "runs": 20_000, "emails": 5_000, "incident_notes": 20_000}
    NOTES_PER_INCIDENT = 50
    SIGNATURES_CAP = 20_000

    def prune(self, days: int = 90) -> dict[str, int]:
        """Rotate everything Warden stores. `days` = retention for the audit trail (actions, runs). Returns rows deleted."""
        t, d, r = now(), 86400, self.RETENTION
        deleted: dict[str, int] = {}

        def rm(label: str, sql: str, args=()):
            with self.lock:
                n = self.conn.execute(sql, args).rowcount
            if n > 0:
                deleted[label] = deleted.get(label, 0) + n

        rm("events", "DELETE FROM events WHERE processed=1 AND severity='info' AND ts<?", (t - r["events_info"] * d,))
        rm("events", "DELETE FROM events WHERE ts<?", (t - r["events"] * d,))
        rm("actions", "DELETE FROM actions WHERE ts<?", (t - days * d,))
        rm("runs", "DELETE FROM runs WHERE started<?", (t - days * d,))
        rm("emails", "DELETE FROM emails WHERE ts<? AND (sent=1 OR error!='queued')", (t - r["emails"] * d,))
        rm("bans", "DELETE FROM bans WHERE active=0 AND expires<?", (t - r["bans_inactive"] * d,))
        rm("trusted_ips", "DELETE FROM trusted_ips WHERE last_seen<?", (t - r["trusted_ips"] * d,))
        rm("log_signatures", "DELETE FROM log_signatures WHERE last_seen<?", (t - r["signatures_unseen"] * d,))
        rm("log_signatures", "DELETE FROM log_signatures WHERE sig IN (SELECT sig FROM log_signatures ORDER BY last_seen DESC LIMIT -1 OFFSET ?)", (self.SIGNATURES_CAP,))
        rm("triggers", "DELETE FROM triggers WHERE enabled=0 AND builtin=0 AND COALESCE(updated_at,created_at,0)<? AND COALESCE(last_eval,0)<?",
           (t - r["triggers_disabled"] * d, t - r["triggers_disabled"] * d))
        old = [x["id"] for x in self.q("SELECT id FROM incidents WHERE status='resolved' AND updated<?", (t - r["incidents_resolved"] * d,))]
        for iid in old:
            rm("incident_notes", "DELETE FROM incident_notes WHERE incident_id=?", (iid,))
            rm("incidents", "DELETE FROM incidents WHERE id=?", (iid,))
        for row in self.q("SELECT incident_id, COUNT(*) n FROM incident_notes GROUP BY incident_id HAVING n>?", (self.NOTES_PER_INCIDENT,)):
            rm("incident_notes", "DELETE FROM incident_notes WHERE incident_id=? AND id NOT IN (SELECT id FROM incident_notes WHERE incident_id=? ORDER BY id DESC LIMIT ?)",
               (row["incident_id"], row["incident_id"], self.NOTES_PER_INCIDENT))
        for table, cap in self.ROW_CAPS.items():  # keep the newest `cap` rows
            rm(table, f"DELETE FROM {table} WHERE id <= (SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET ?)", (cap,))
        for rt in self.q("SELECT name, suppress FROM routines WHERE suppress!='[]'"):
            sup = json.loads(rt["suppress"] or "[]")
            live = [x for x in sup if not x.get("expires") or x["expires"] > t]
            if len(live) != len(sup):
                self.x("UPDATE routines SET suppress=? WHERE name=?", (json.dumps(live), rt["name"]))
                deleted["suppressions"] = deleted.get("suppressions", 0) + len(sup) - len(live)
        return deleted

    def compact_storage(self) -> None:
        """Return freed pages to the filesystem and keep the WAL file from growing."""
        if self.path == ":memory:":
            return
        with self.lock:
            free = self.conn.execute("PRAGMA freelist_count").fetchone()[0]
            total = self.conn.execute("PRAGMA page_count").fetchone()[0] or 1
            mode = self.conn.execute("PRAGMA auto_vacuum").fetchone()[0]
            if free > 1000 and free / total > 0.2:
                # incremental_vacuum frees one page per result row: it must be fully stepped (fetchall)
                self.conn.execute("PRAGMA incremental_vacuum" if mode == 2 else "VACUUM").fetchall()
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def size_bytes(self) -> int:
        try:
            return sum(Path(self.path + suffix).stat().st_size for suffix in ("", "-wal") if Path(self.path + suffix).exists())
        except OSError:
            return 0
