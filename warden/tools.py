"""Tools exposed to the LLM. Every call is gated by autonomy + safety and written to the audit log."""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from warden import routines as routines_mod
from warden import safety, triggers as triggers_mod, util
from warden.config import AUTONOMY_LEVELS, NFT_TUNABLES, SEVERITIES, TUNABLE, apply_overrides


@dataclass
class ToolContext:
    settings: object
    db: object
    bans: object = None
    firewall: object = None
    mailer: object = None
    sampler: object = None
    run_id: int | None = None
    actor: str = "agent"
    result: dict | None = None
    changes: list[str] = field(default_factory=list)
    emailed: bool = False


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    handler: Callable
    level: str = "observe"  # minimum autonomy

    def schema(self) -> dict:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}


def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or [], "additionalProperties": False}


S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
SEV = {"type": "string", "enum": SEVERITIES}


# ── shell & files ──────────────────────────────────────────────────────────
def t_run_command(ctx: ToolContext, command: str, reason: str = "", timeout: int = 120) -> str:
    v = safety.check_command(command, ctx.settings.allow_reboot, ctx.bans.is_protected if ctx.bans else None)
    if not v.allowed:
        return f"BLOCKED by safety policy: {v.reason}"
    ro = safety.is_read_only(command)
    if not ctx.settings.autonomy_at_least("full") and not ro.allowed:
        return f"BLOCKED: autonomy is '{ctx.settings.autonomy}', only read-only commands are allowed ({ro.reason})"
    res = util.run(command, timeout=max(1, min(int(timeout or 120), 900)))
    if not ro.allowed:
        ctx.changes.append(f"ran `{command[:200]}` -> exit {res.code}" + (f" ({reason[:120]})" if reason else ""))
    return res.render()


def t_read_file(ctx: ToolContext, path: str, tail_lines: int = 0, grep: str = "", max_bytes: int = 20000) -> str:
    if safety.is_secret_path(path):
        return "BLOCKED: secret file (credentials/keys are never sent to the LLM)"
    p = Path(path)
    if not p.is_file():
        return f"ERROR: {path} is not a regular file" + (" (it is a directory; use run_command ls)" if p.is_dir() else "")
    max_bytes = max(1000, min(int(max_bytes or 20000), 100000))
    try:
        size = p.stat().st_size
        with open(p, "rb") as fh:
            if tail_lines or size > max_bytes * 4:
                fh.seek(max(0, size - max_bytes * 4))
            data = fh.read(max_bytes * 4)
    except OSError as exc:
        return f"ERROR: {exc}"
    if b"\x00" in data[:4096]:
        return f"{path}: binary file ({size} bytes)"
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    if grep:
        try:
            rx = re.compile(grep)
        except re.error as exc:
            return f"ERROR: bad grep regex: {exc}"
        lines = [ln for ln in lines if rx.search(ln)]
    if tail_lines:
        lines = lines[-int(tail_lines):]
    out = "\n".join(lines)
    return f"{path} ({size} bytes{', showing tail' if size > max_bytes * 4 else ''}):\n" + util.truncate(out, max_bytes)


def _write(ctx: ToolContext, path: str, content: str, reason: str, mode: str | None = None, validate_command: str | None = None) -> str:
    denied = safety.write_denied(path)
    if denied:
        return f"BLOCKED: {denied}"
    p = Path(os.path.normpath(path))
    if p.is_dir():
        return f"ERROR: {path} is a directory"
    if validate_command:
        v = safety.check_command(validate_command, ctx.settings.allow_reboot)
        if not v.allowed:
            return f"BLOCKED validate_command: {v.reason}"
    backup = None
    st = None
    if p.exists():
        st = p.stat()
        backup = ctx.settings.backup_dir / time.strftime("%Y%m%d-%H%M%S") / str(p).lstrip("/")
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, backup)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.warden-tmp")
    tmp.write_text(content, encoding="utf-8")
    if st:
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o7777)
    if mode:
        os.chmod(tmp, int(mode, 8))
    elif re.match(r"^/etc/sudoers(\.d/|$)", str(p)):
        os.chmod(tmp, 0o440)
    os.replace(tmp, p)
    for vcmd in [c for c in (safety.validator_for(str(p)), validate_command) if c]:
        cmd = vcmd.replace("{path}", shlex.quote(str(p)))
        res = util.run(cmd, timeout=60)
        if not res.ok:
            if backup:
                shutil.copy2(backup, p)
            else:
                p.unlink(missing_ok=True)
            return f"VALIDATION FAILED with `{cmd}` — change ROLLED BACK.\n{res.render(3000)}"
    ctx.changes.append(f"wrote {p}" + (f" (backup {backup})" if backup else " (new file)") + (f": {reason[:150]}" if reason else ""))
    return f"OK: wrote {len(content)} bytes to {p}" + (f"; backup at {backup}" if backup else "") + "; validation passed"


def t_write_file(ctx, path: str, content: str, reason: str, mode: str = "", validate_command: str = "") -> str:
    return _write(ctx, path, content, reason, mode or None, validate_command or None)


def t_replace_in_file(ctx, path: str, old: str, new: str, reason: str, count: int = 1) -> str:
    if safety.is_secret_path(path):
        return "BLOCKED: secret file"
    p = Path(path)
    if not p.is_file():
        return f"ERROR: {path} is not a regular file"
    text = p.read_text(encoding="utf-8", errors="replace")
    n = text.count(old)
    if n == 0:
        return "ERROR: `old` text not found (read the file first; whitespace must match exactly)"
    if count and n > count:
        return f"ERROR: `old` occurs {n} times; make it unique or pass count={n}"
    return _write(ctx, path, text.replace(old, new, count or n), reason)


# ── firewall ───────────────────────────────────────────────────────────────
def t_block_ip(ctx, target: str, reason: str, minutes: int = 0, edge: bool = False) -> str:
    ok, msg = ctx.bans.ban(target, reason, f"agent:{ctx.actor}", minutes or None, edge=edge)
    if ok:
        ctx.changes.append(f"{msg}: {reason[:150]}")
    return msg


def t_unblock_ip(ctx, target: str, reason: str) -> str:
    ok, msg = ctx.bans.unban(target, reason, f"agent:{ctx.actor}")
    if ok:
        ctx.changes.append(f"{msg}: {reason[:150]}")
    return msg


def t_list_blocked(ctx) -> str:
    rows = ctx.db.bans_active()
    if not rows:
        return "no active bans"
    return f"{len(rows)} active bans:\n" + "\n".join(
        f"{r['ip']} until {util.iso(r['expires'])} (#{r['count']}, {r['source']}): {r['reason'][:150]}" for r in rows[:200]
    )


# ── incidents ──────────────────────────────────────────────────────────────
def t_open_incident(ctx, title: str, severity: str, details: str, follow_up_minutes: int = 30) -> str:
    for i in ctx.db.incidents_active():
        if i["title"].strip().lower() == title.strip().lower():
            return f"incident #{i['id']} with this title is already active; use update_incident"
    iid = ctx.db.incident_open(title, severity, details, time.time() + max(15, int(follow_up_minutes)) * 60)
    ctx.db.incident_note(iid, ctx.actor, f"opened: {details[:2000]}")
    ctx.changes.append(f"opened incident #{iid} [{severity}] {title}")
    return f"opened incident #{iid}; follow-up in {follow_up_minutes} min"


def t_update_incident(ctx, id: int, note: str, status: str = "", severity: str = "", follow_up_minutes: int = 0, summary: str = "") -> str:
    inc = ctx.db.incident(id)
    if not inc:
        return f"ERROR: no incident #{id}"
    fields = {}
    if summary:
        fields["details"] = summary[:4000]
    if status in ("open", "monitoring", "needs_human"):
        fields["status"] = status
    if severity in SEVERITIES:
        fields["severity"] = severity
    if follow_up_minutes:
        fields["next_check"] = time.time() + max(15, int(follow_up_minutes)) * 60
    if fields:
        ctx.db.incident_update(id, **fields)
    ctx.db.incident_note(id, ctx.actor, note)
    return f"incident #{id} updated" + (f" ({fields.get('status', inc['status'])}, next check in {follow_up_minutes} min)" if follow_up_minutes else "")


def t_resolve_incident(ctx, id: int, resolution: str) -> str:
    inc = ctx.db.incident(id)
    if not inc:
        return f"ERROR: no incident #{id}"
    ctx.db.incident_update(id, status="resolved", resolution=resolution[:2000], next_check=None)
    ctx.db.incident_note(id, ctx.actor, f"RESOLVED: {resolution}")
    # disarm triggers linked to this incident
    for t in ctx.db.triggers():
        if t["incident_id"] == id and t["enabled"]:
            ctx.db.trigger_set(t["id"], incident_id=None)
    ctx.changes.append(f"resolved incident #{id} {inc['title']}: {resolution[:200]}")
    return f"incident #{id} resolved"


def t_list_incidents(ctx, include_resolved: bool = False) -> str:
    rows = ctx.db.q("SELECT * FROM incidents " + ("" if include_resolved else "WHERE status!='resolved' ") + "ORDER BY id DESC LIMIT 30")
    if not rows:
        return "no incidents"
    out = []
    for r in rows:
        notes = ctx.db.incident_notes(r["id"], limit=3)
        out.append(f"#{r['id']} [{r['status']}/{r['severity']}] {r['title']} checks={r['checks']} next={util.ago(r['next_check'])}\n"
                   + "\n".join(f"   - {util.iso(n['ts'])} {n['note'][:300]}" for n in notes))
    return "\n".join(out)


# ── routines ───────────────────────────────────────────────────────────────
def t_list_routines(ctx) -> str:
    out = []
    for r in ctx.db.routines():
        cols = "; ".join(f"{c['name']}[{c.get('gate', 'changed')}]: {c['command'][:120]}" for c in r["collectors"])
        sup = "; ".join(f"{x['collector']}: /{x['pattern']}/ ({x.get('reason', '')[:60]})" for x in r["suppress"]) or "-"
        out.append(f"{r['name']} enabled={r['enabled']} gated={r['gated']} every={r['interval_minutes']}m protected={r['protected']} "
                   f"next={util.ago(r['next_run'])} last={r['last_status']}\n  description: {r['description']}\n  collectors: {cols}\n"
                   f"  suppressions: {sup}\n  instructions: {r['instructions'][:400]}")
    return "\n".join(out) or "(none)"


def t_upsert_routine(ctx, name: str, interval_minutes: int = 0, description: str = "", instructions: str = "",
                     collectors: list | None = None, enabled: bool | None = None, gated: bool | None = None, run_now: bool = False) -> str:
    existing = ctx.db.routine(name)
    if not existing and len(ctx.db.routines()) >= routines_mod.MAX_ROUTINES:
        return f"ERROR: routine limit ({routines_mod.MAX_ROUTINES}) reached; delete one first"
    patch: dict = {"name": name}
    if enabled is not None:
        patch["enabled"] = enabled
    if interval_minutes:
        patch["interval_minutes"] = interval_minutes
    if description:
        patch["description"] = description
    if instructions:
        patch["instructions"] = instructions
    if collectors is not None:
        patch["collectors"] = collectors
    if gated is not None:
        patch["gated"] = gated
    r, err = routines_mod.validate_routine(patch, existing)
    if err:
        return f"ERROR: {err}"
    r["next_run"] = time.time()
    ctx.db.routine_upsert(r, ctx.actor)
    if run_now:
        ctx.db.routine_set(name, next_run=time.time())
    elif existing and interval_minutes and existing.get("last_run"):
        ctx.db.routine_set(name, next_run=existing["last_run"] + interval_minutes * 60)
    ctx.changes.append(f"{'updated' if existing else 'created'} routine '{name}' (every {r['interval_minutes']}m, enabled={r['enabled']})")
    return f"routine '{name}' {'updated' if existing else 'created'}"


def t_suppress_signal(ctx, routine: str, collector: str, pattern: str, reason: str, expires_in_days: int = 90, remove: bool = False) -> str:
    r = ctx.db.routine(routine)
    if not r:
        return f"ERROR: no routine {routine}"
    if collector != "*" and collector not in {c["name"] for c in r["collectors"]}:
        return f"ERROR: routine {routine} has no collector {collector}"
    sup = [x for x in r["suppress"] if not (x["collector"] == collector and x["pattern"] == pattern)]
    if remove:
        ctx.db.routine_set(routine, suppress=sup)
        ctx.changes.append(f"removed suppression {routine}/{collector} /{pattern}/")
        return "suppression removed"
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return f"ERROR: bad regex: {exc}"
    if rx.search("") is not None or len(pattern) < 4:
        return "ERROR: pattern too broad (it matches everything); make it specific"
    if len(sup) >= 50:
        return "ERROR: too many suppressions on this routine; remove stale ones first"
    days = max(1, min(365, int(expires_in_days)))
    sup.append({"collector": collector, "pattern": pattern, "reason": reason[:200], "expires": time.time() + days * 86400})
    ctx.db.routine_set(routine, suppress=sup)
    ctx.changes.append(f"suppressed {routine}/{collector} lines matching /{pattern}/ for {days}d: {reason[:120]}")
    return f"lines matching /{pattern}/ in {routine}/{collector} will no longer wake you (expires in {days} days)"


def t_delete_routine(ctx, name: str, reason: str) -> str:
    r = ctx.db.routine(name)
    if not r:
        return f"ERROR: no routine {name}"
    if r["protected"]:
        return f"ERROR: {name} is protected; you may change its interval within bounds but not delete it"
    ctx.db.routine_delete(name)
    ctx.changes.append(f"deleted routine '{name}': {reason[:150]}")
    return f"deleted routine {name}"


# ── triggers ───────────────────────────────────────────────────────────────
def t_list_triggers(ctx) -> str:
    out = []
    for t in ctx.db.triggers():
        out.append(f"{t['name']} [{t['kind']}] enabled={t['enabled']} sev={t['severity']} every={t['interval_s']}s cooldown={t['cooldown_s']}s "
                   f"consecutive={t['consecutive']} fired={t['fire_count']}x last={util.ago(t['last_fired'])} value={t['last_value']} "
                   f"expires={util.iso(t['expires_at'])} incident={t['incident_id']}\n  spec={json.dumps(t['spec'])}\n  instructions={t['instructions'][:300]}")
    return "\n".join(out) or "(none)"


def t_upsert_trigger(ctx, name: str, kind: str, spec: dict, severity: str = "medium", interval_s: int = 60, cooldown_s: int = 1800,
                     consecutive: int = 1, instructions: str = "", once: bool = False, expires_in_minutes: int = 0,
                     incident_id: int | None = None, enabled: bool = True) -> str:
    existing = ctx.db.trigger(name)
    if not existing and len(ctx.db.triggers()) >= triggers_mod.MAX_TRIGGERS:
        return f"ERROR: trigger limit ({triggers_mod.MAX_TRIGGERS}) reached; delete stale ones first"
    t, err = triggers_mod.validate(dict(name=name, kind=kind, spec=spec, severity=severity, interval_s=interval_s, cooldown_s=cooldown_s,
                                        consecutive=consecutive, instructions=instructions, once=once, expires_in_minutes=expires_in_minutes,
                                        incident_id=incident_id, enabled=enabled))
    if err:
        return f"ERROR: {err}"
    ctx.db.trigger_upsert(t, ctx.actor)
    ctx.changes.append(f"{'updated' if existing else 'armed'} trigger '{name}' ({kind}: {json.dumps(t['spec'])[:150]})")
    return f"trigger '{name}' {'updated' if existing else 'created'}; it is evaluated every {t['interval_s']}s by the sentinel"


def t_delete_trigger(ctx, name: str, reason: str) -> str:
    if not ctx.db.trigger(name):
        return f"ERROR: no trigger {name}"
    ctx.db.trigger_delete(name)
    ctx.changes.append(f"deleted trigger '{name}': {reason[:150]}")
    return f"deleted trigger {name}"


def t_test_trigger(ctx, kind: str, spec: dict) -> str:
    t, err = triggers_mod.validate({"name": "test-probe", "kind": kind, "spec": spec})
    if err:
        return f"ERROR: {err}"
    try:
        hit, value, detail, _ = triggers_mod.evaluate({**t, "state": {}}, ctx.sampler)
    except Exception as exc:  # noqa: BLE001
        return f"ERROR evaluating: {exc}"
    note = " (change-based kinds never match on the first evaluation)" if kind == "file" or spec.get("fire_on") == "changed" else ""
    return f"would fire: {hit}{note}\nvalue: {value}\n{detail}"


# ── memory / tuning / notify / finish ──────────────────────────────────────
MEMORY_MAX_KEYS = 40
MEMORY_MAX_CHARS = 6000  # total; memory is injected into every run, so it must stay small


def t_remember(ctx, key: str, value: str) -> str:
    if not re.match(r"^[\w.:-]{1,64}$", key):
        return "ERROR: key must be 1-64 chars of [A-Za-z0-9_.:-]"
    value = value.strip()[:400]
    others = [m for m in ctx.db.memory_all() if m["key"] != key]
    if len(others) >= MEMORY_MAX_KEYS:
        return f"ERROR: memory has {MEMORY_MAX_KEYS} keys; consolidate first (merge related facts into one key, forget stale ones)"
    used = sum(len(m["key"]) + len(m["value"]) for m in others)
    if used + len(key) + len(value) > MEMORY_MAX_CHARS:
        return f"ERROR: memory is full ({used}/{MEMORY_MAX_CHARS} chars); consolidate: rewrite related keys more concisely or forget stale ones"
    ctx.db.memory_set(key, value)
    return f"remembered {key} (memory {used + len(key) + len(value)}/{MEMORY_MAX_CHARS} chars)"


def t_forget(ctx, key: str) -> str:
    return f"forgot {key}" if ctx.db.memory_del(key) else f"no memory key {key}"


def t_tune_sentinel(ctx, setting: str, value: int, reason: str) -> str:
    if setting not in TUNABLE:
        return f"ERROR: tunable settings: {', '.join(f'{k} {v}' for k, v in TUNABLE.items())}"
    lo, hi = TUNABLE[setting]
    v = max(lo, min(hi, int(value)))
    old = getattr(ctx.settings, setting)
    ctx.db.kv_set(f"tune.{setting}", str(v))
    apply_overrides(ctx.settings, {setting: str(v)})
    note = ""
    if setting in NFT_TUNABLES and ctx.firewall is not None and getattr(ctx.firewall, "ready", False):
        # rebuild our nftables table with the new limits, then re-apply allowlist and active bans
        if ctx.firewall.setup():
            ctx.firewall.set_allowlist(ctx.settings.allowlist + ctx.bans.proxies.cidrs())
            note = f"; firewall reloaded, {ctx.bans.restore()} bans re-applied"
        else:
            note = f"; firewall reload FAILED: {ctx.firewall.last_error}"
    ctx.changes.append(f"tuned {setting}: {old} -> {v} ({reason[:150]}){note}")
    return f"{setting}: {old} -> {v}{note}"


def t_send_email(ctx, title: str, body: str, severity: str = "high") -> str:
    if not ctx.mailer:
        return "ERROR: mailer unavailable"
    status = ctx.mailer.notify(title, body, severity)
    ctx.emailed = ctx.emailed or status == "sent"
    return status


def t_finish(ctx, status: str, severity: str, title: str, summary: str, notify: bool) -> str:
    ctx.result = {"status": status, "severity": severity if severity in SEVERITIES else "info", "title": title[:150], "summary": summary, "notify": bool(notify)}
    return "finished"


TOOLS: list[Tool] = [
    Tool("run_command", "Run a bash command as root (timeout default 120s, max 900). Output is truncated. Denylisted destructive commands are blocked; below 'full' autonomy only read-only commands run.",
         _obj({"command": S, "reason": {"type": "string", "description": "why (logged)"}, "timeout": I}, ["command"]), t_run_command),
    Tool("read_file", "Read a text file (optionally only the last N lines or lines matching a regex). Secret files are blocked.",
         _obj({"path": S, "tail_lines": I, "grep": S, "max_bytes": I}, ["path"]), t_read_file),
    Tool("write_file", "Create/overwrite a file atomically. Existing files are backed up; known configs (sshd, sudoers, nginx, apache, nftables, fstab...) are validated and ROLLED BACK if invalid. Optional extra validate_command ({path} placeholder). mode e.g. '0644'.",
         _obj({"path": S, "content": S, "reason": S, "mode": S, "validate_command": S}, ["path", "content", "reason"]), t_write_file, "full"),
    Tool("replace_in_file", "Replace exact text in a file (safer than rewriting it). Same backup/validation/rollback as write_file.",
         _obj({"path": S, "old": S, "new": S, "reason": S, "count": I}, ["path", "old", "new", "reason"]), t_replace_in_file, "full"),
    Tool("block_ip", "Ban an IP or CIDR (>= /16 v4, >= /32 v6) in nftables for `minutes` (default: escalating by offence count). Protected IPs (allowlist, trusted, own, Cloudflare) are refused. "
         "edge=true also blocks the IP at the Cloudflare edge (when configured) — required for web traffic that arrives via Cloudflare, where host bans have no effect.",
         _obj({"target": S, "reason": S, "minutes": I, "edge": B}, ["target", "reason"]), t_block_ip, "contain"),
    Tool("unblock_ip", "Remove a ban (e.g. false positive).", _obj({"target": S, "reason": S}, ["target", "reason"]), t_unblock_ip, "contain"),
    Tool("list_blocked", "List active bans.", _obj({}), t_list_blocked),
    Tool("open_incident", "Track a problem that needs follow-up. You will be woken after follow_up_minutes to continue until resolved.",
         _obj({"title": S, "severity": SEV, "details": S, "follow_up_minutes": I}, ["title", "severity", "details"]), t_open_incident),
    Tool("update_incident", "Add a progress note, rewrite the running `summary` (replaces the incident's state description; old notes are rotated out of view), change status (open|monitoring|needs_human), severity, or reschedule the next follow-up.",
         _obj({"id": I, "note": S, "summary": S, "status": {"type": "string", "enum": ["open", "monitoring", "needs_human"]}, "severity": SEV, "follow_up_minutes": I}, ["id", "note"]), t_update_incident),
    Tool("resolve_incident", "Close an incident once fixed AND verified.", _obj({"id": I, "resolution": S}, ["id", "resolution"]), t_resolve_incident),
    Tool("list_incidents", "List incidents with latest notes.", _obj({"include_resolved": B}), t_list_incidents),
    Tool("list_routines", "List scheduled routines with their collectors and instructions.", _obj({}), t_list_routines),
    Tool("upsert_routine", "Create or modify a scheduled routine. Collectors are read-only shell commands (or internal: " + ", ".join(sorted(routines_mod.INTERNAL)) + ") run every interval WITHOUT the LLM; "
         "gate decides if they wake you: 'changed' (output differs from last review; you get a diff), 'nonempty' (any output — pair with `--since {since}`, "
         "replaced by the last review time), 'context' (shown only when something else woke you). gated=false = always run the LLM. "
         "interval_minutes 5..10080; protected routines can only be retuned within bounds.",
         _obj({"name": S, "interval_minutes": I, "description": S, "instructions": S,
               "collectors": {"type": "array", "items": _obj({"name": S, "command": S, "gate": {"type": "string", "enum": list(routines_mod.GATES)}, "timeout": I}, ["name", "command"])},
               "enabled": B, "gated": B, "run_now": B}, ["name"]), t_upsert_routine),
    Tool("suppress_signal", "Stop benign recurring lines from waking you: lines of routine/collector ('*' = all collectors) matching the regex are dropped before gating. Keep patterns narrow; they expire (default 90 days). remove=true deletes one.",
         _obj({"routine": S, "collector": S, "pattern": S, "reason": S, "expires_in_days": I, "remove": B}, ["routine", "collector", "pattern", "reason"]), t_suppress_signal),
    Tool("delete_routine", "Delete a non-protected routine.", _obj({"name": S, "reason": S}, ["name", "reason"]), t_delete_routine),
    Tool("list_triggers", "List triggers (wake-up conditions) and their state.", _obj({}), t_list_triggers),
    Tool("upsert_trigger",
         "Create/modify a trigger that WAKES YOU when a condition holds. Evaluated without the LLM. Kinds/spec:\n"
         "- metric (from the sentinel's /proc snapshot, free): {metric: " + "|".join(triggers_mod.METRICS) + ", op: >|>=|<|<=|==|!=|increase, value: number, "
         "arg?: mount path (disk_used_pct/inode_used_pct/disk_full_eta_h), device (disk_busy_pct) or port (port_conns, required)}. Without arg, disk metrics use the worst mount. *_ps are per-second rates.\n"
         "- command: {command: <read-only cmd>, fire_on: exit_nonzero|exit_zero|match|no_match|numeric|changed, pattern?: regex, op?, value?, timeout?}\n"
         "- log (real time from the journal stream): {pattern: regex, unit?: 'nginx.service', identifier?: 'sshd', priority?: 'err', min_count: N, window_s: S}\n"
         "- service: {unit: 'nginx.service'}  (fires when not active)\n"
         "- port: {port: 443, host?: '127.0.0.1', timeout?: 5}  (fires when connect fails)\n"
         "- file: {path: '/etc/x'}  (fires when content hash changes)\n"
         "consecutive = matches needed in a row; cooldown_s between firings; once = disable after first firing; expires_in_minutes = auto-disable; "
         "incident_id links it to an incident (recovery wakes that incident). instructions are shown to you when it fires.",
         _obj({"name": S, "kind": {"type": "string", "enum": list(triggers_mod.KINDS)}, "spec": {"type": "object"}, "severity": SEV,
               "interval_s": I, "cooldown_s": I, "consecutive": I, "instructions": S, "once": B, "expires_in_minutes": I,
               "incident_id": I, "enabled": B}, ["name", "kind", "spec"]), t_upsert_trigger),
    Tool("delete_trigger", "Delete a trigger.", _obj({"name": S, "reason": S}, ["name", "reason"]), t_delete_trigger),
    Tool("test_trigger", "Evaluate a trigger definition once right now (does not save or fire). Use it to check a trigger before arming it.",
         _obj({"kind": {"type": "string", "enum": list(triggers_mod.KINDS)}, "spec": {"type": "object"}}, ["kind", "spec"]), t_test_trigger),
    Tool("remember", "Store a durable fact about this host (shown in every future run, so keep it concise: max 400 chars per key, 6000 total), e.g. role, expected services/ports, operator preferences, known-good anomalies. Re-using a key overwrites it.",
         _obj({"key": S, "value": S}, ["key", "value"]), t_remember),
    Tool("forget", "Delete a memory key.", _obj({"key": S}, ["key"]), t_forget),
    Tool("tune_sentinel", "Adjust a sentinel threshold (bounded): " + ", ".join(f"{k} {v}" for k, v in TUNABLE.items()),
         _obj({"setting": {"type": "string", "enum": list(TUNABLE)}, "value": I, "reason": S}, ["setting", "value", "reason"]), t_tune_sentinel),
    Tool("send_email", "Email the operator immediately (use for urgent mid-run alerts; the final report is sent via finish).",
         _obj({"title": S, "body": S, "severity": SEV}, ["title", "body"]), t_send_email),
    Tool("finish", "End this run. summary = plain-text report for the operator: what you found, what you did (and verification), what remains/recommendations. notify=true emails it.",
         _obj({"status": {"type": "string", "enum": ["ok", "issues_found", "action_taken", "needs_human"]}, "severity": SEV, "title": S, "summary": S, "notify": B},
              ["status", "severity", "title", "summary", "notify"]), t_finish),
]
TOOLS_BY_NAME = {t.name: t for t in TOOLS}


class Toolbox:
    def __init__(self, settings):
        self.settings = settings

    def available(self) -> list[Tool]:
        lvl = AUTONOMY_LEVELS.index(self.settings.autonomy)
        return [t for t in TOOLS if AUTONOMY_LEVELS.index(t.level) <= lvl]

    def schemas(self) -> list[dict]:
        return [t.schema() for t in self.available()]

    def dispatch(self, ctx: ToolContext, name: str, args: dict, parse_error: str | None = None) -> str:
        tool = TOOLS_BY_NAME.get(name)
        if parse_error:
            out, ok = f"ERROR: {parse_error}. Send arguments as a JSON object.", False
        elif not tool:
            out, ok = f"ERROR: unknown tool {name}", False
        elif tool not in self.available():
            out, ok = f"BLOCKED: {name} requires autonomy '{tool.level}' (current: {self.settings.autonomy})", False
        else:
            try:
                out = tool.handler(ctx, **args)
                ok = not out.startswith(("ERROR", "BLOCKED", "VALIDATION FAILED"))
            except TypeError as exc:
                out, ok = f"ERROR: bad arguments for {name}: {exc}", False
            except Exception as exc:  # noqa: BLE001 — report tool failures to the model, don't crash the run
                out, ok = f"ERROR: {type(exc).__name__}: {exc}", False
        ctx.db.audit(ctx.run_id, ctx.actor, name, args, out, ok)
        return out
