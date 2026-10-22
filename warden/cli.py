"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import sys
import time

from warden import __version__, util
from warden.config import SEVERITIES, load_settings


def _warden(args, attach=True):
    from warden.daemon import Warden

    return Warden(_settings(args), attach_firewall=attach)


def _settings(args):
    if not hasattr(args, "_settings"):
        args._settings = load_settings()
        if args.observe:
            args._settings.autonomy = "observe"
    return args._settings


def _signal_daemon(settings) -> bool:
    try:
        pid = int(settings.pid_path.read_text().strip())
        os.kill(pid, signal.SIGUSR1)
        return True
    except (OSError, ValueError):
        return False


def _print_result(res) -> None:
    if res is None:
        print("(no LLM run: no gate fired, budget exhausted, or LLM unavailable — see `warden status` / `warden check`)")
        return
    print(f"\n== {res.title} ==\nstatus={res.status} severity={res.severity} notify={res.notify} steps={res.steps} "
          f"tokens in={res.tokens_in} (cached {res.tokens_cached}) out={res.tokens_out}")
    if res.error:
        print(f"error: {res.error}")
    print(f"\n{res.summary}")
    if res.changes:
        print("\nChanges:\n" + "\n".join(f"- {c}" for c in res.changes))


# ── commands ───────────────────────────────────────────────────────────────
def cmd_daemon(args) -> int:
    from warden.daemon import Daemon

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s", force=True)
    return Daemon(_settings(args)).start()


def cmd_status(args) -> int:
    w = _warden(args)
    db = w.db
    pid_alive = False
    try:
        pid = int(w.s.pid_path.read_text())
        os.kill(pid, 0)
        pid_alive = True
    except (OSError, ValueError):
        pass
    print(f"Warden {__version__} · host {w.s.hostname} · daemon {'RUNNING' if pid_alive else 'not running'} · autonomy {w.s.autonomy}")
    print(f"LLM: {w.llm.label if w.llm else 'UNAVAILABLE: ' + str(w.llm_error)} · firewall table: {'present' if w.firewall.ready else 'absent'}"
          f" · email: {'configured' if w.s.email_configured else 'NOT configured'}")
    print("\nRoutines:")
    for r in db.routines():
        print(f"  {'*' if r['enabled'] else ' '} {r['name']:<16} every {r['interval_minutes']:>5}m {'gated ' if r['gated'] else 'always'}  "
              f"last {util.ago(r['last_run']):>12} [{r['last_status'] or '-'}]  next {util.ago(r['next_run'])}  suppressions {len(r['suppress'])}")
    trig = db.triggers()
    print(f"\nTriggers: {sum(t['enabled'] for t in trig)} enabled / {len(trig)}")
    for t in sorted(trig, key=lambda t: -(t["last_fired"] or 0))[:8]:
        if t["fire_count"]:
            print(f"  {t['name']:<30} fired {t['fire_count']}x, last {util.ago(t['last_fired'])}")
    inc = db.incidents_active()
    print(f"\nActive incidents: {len(inc)}")
    for i in inc:
        print(f"  #{i['id']} [{i['status']}/{i['severity']}] {i['title']} (checks {i['checks']}, next {util.ago(i['next_check'])})")
    bans = db.bans_active()
    print(f"\nActive bans: {len(bans)}")
    for b in bans[:10]:
        print(f"  {b['ip']:<40} until {util.iso(b['expires'])}  {b['reason'][:70]}")
    pend = db.pending_events()
    print(f"\nPending events: {len(pend)}")
    onboarded = db.kv_get("onboarded")
    print(f"\nOnboarded: {util.iso(float(onboarded)) if onboarded else 'not yet'} · "
          f"LLM tokens last 24h (effective): {w.tokens_last_24h():,.0f} / budget {w.s.daily_token_budget:,}")
    runs = db.q("SELECT * FROM runs ORDER BY id DESC LIMIT 8")
    print("\nRecent LLM runs:")
    for r in runs:
        print(f"  {util.iso(r['started'])} {r['kind']}/{r['name']:<18} {r['status'] or '':<12} {r['severity'] or '':<8} "
              f"tokens in {r['tokens_in']} (cached {r['tokens_cached'] or 0}) out {r['tokens_out']}")
    return 0


def cmd_run(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", force=True)
    w = _warden(args)
    w.seed()
    if not w.db.routine(args.name):
        print(f"no routine {args.name}; available: {', '.join(r['name'] for r in w.db.routines())}")
        return 1
    _print_result(w.run_routine(args.name, force=args.force))
    return 0


def cmd_onboard(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", force=True)
    w = _warden(args)
    w.seed()
    _print_result(w.run_onboarding())
    return 0


def cmd_ask(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", force=True)
    w = _warden(args)
    _print_result(w.ask(" ".join(args.text)))
    return 0


def cmd_event(args) -> int:
    w = _warden(args, attach=False)
    eid = w.db.add_event("external", args.kind, args.severity, " ".join(args.message))
    woke = _signal_daemon(w.s)
    print(f"event #{eid} recorded" + (" and daemon woken" if woke else " (daemon not running; it will be processed on start)"))
    return 0


def cmd_incidents(args) -> int:
    w = _warden(args, attach=False)
    if args.id:
        i = w.db.incident(args.id)
        if not i:
            print("not found")
            return 1
        print(f"#{i['id']} [{i['status']}/{i['severity']}] {i['title']}\nopened {util.iso(i['created'])}, checks {i['checks']}, next {util.ago(i['next_check'])}\n\n{i['details']}\n")
        for n in w.db.incident_notes(i["id"], limit=200):
            print(f"{util.iso(n['ts'])} [{n['author']}] {n['note']}\n")
        if i["resolution"]:
            print(f"Resolution: {i['resolution']}")
        return 0
    rows = w.db.q("SELECT * FROM incidents " + ("" if args.all else "WHERE status!='resolved' ") + "ORDER BY id DESC LIMIT 100")
    for i in rows:
        print(f"#{i['id']:<4} {i['status']:<12} {i['severity']:<8} {util.iso(i['created'])}  {i['title']}")
    if not rows:
        print("no incidents")
    return 0


def cmd_resolve(args) -> int:
    w = _warden(args, attach=False)
    w.db.incident_update(args.id, status="resolved", resolution=" ".join(args.resolution) or "resolved by operator", next_check=None)
    w.db.incident_note(args.id, "operator", "resolved by operator: " + (" ".join(args.resolution) or "-"))
    print(f"incident #{args.id} resolved")
    return 0


def cmd_bans(args) -> int:
    w = _warden(args, attach=False)
    for b in w.db.bans_active():
        print(f"{b['ip']:<40} until {util.iso(b['expires'])} #{b['count']} {b['source']:<16} {b['reason'][:90]}")
    return 0


def cmd_ban(args) -> int:
    w = _warden(args)
    ok, msg = w.bans.ban(args.ip, args.reason, "operator", args.minutes)
    print(msg)
    return 0 if ok else 1


def cmd_unban(args) -> int:
    w = _warden(args)
    ok, msg = w.bans.unban(args.ip, "operator request", "operator")
    print(msg)
    return 0 if ok else 1


def cmd_routines(args) -> int:
    w = _warden(args, attach=False)
    w.seed()
    if args.action in ("enable", "disable"):
        r = w.db.routine(args.name or "")
        if not r:
            print("no such routine")
            return 1
        if args.action == "disable" and r["protected"]:
            print(f"{r['name']} is protected")
            return 1
        w.db.routine_set(r["name"], enabled=1 if args.action == "enable" else 0)
        print(f"{r['name']} {args.action}d")
        return 0
    for r in w.db.routines():
        print(f"{'*' if r['enabled'] else ' '} {r['name']:<16} every {r['interval_minutes']}m {'gated ' if r['gated'] else 'always'}  {r['description']}")
        if args.verbose:
            for c in r["collectors"]:
                print(f"      - {c['name']} [{c.get('gate', 'changed')}]: {c['command']}")
            for x in r["suppress"]:
                print(f"      ~ suppress {x['collector']}: /{x['pattern']}/ ({x.get('reason', '')})")
    return 0


def cmd_triggers(args) -> int:
    w = _warden(args, attach=False)
    w.seed()
    if args.action in ("enable", "disable", "delete"):
        t = w.db.trigger(args.name or "")
        if not t:
            print("no such trigger")
            return 1
        if args.action == "delete":
            w.db.trigger_delete(t["name"])
        else:
            w.db.trigger_set(t["id"], enabled=1 if args.action == "enable" else 0)
        print(f"{t['name']} {args.action}d")
        return 0
    for t in w.db.triggers():
        print(f"{'*' if t['enabled'] else ' '} {t['name']:<30} {t['kind']:<8} {t['severity']:<8} every {t['interval_s']}s fired {t['fire_count']}x "
              f"last={util.ago(t['last_fired'])} value={t['last_value']}")
        if args.verbose:
            print(f"      spec={json.dumps(t['spec'])}  by={t['created_by']}")
    return 0


def cmd_log(args) -> int:
    w = _warden(args, attach=False)
    for a in reversed(w.db.q("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (args.n,))):
        print(f"{util.iso(a['ts'])} {'ok ' if a['ok'] else 'ERR'} {a['actor']:<22} {a['tool']:<16} {a['args'][:160]}")
    return 0


def cmd_test_llm(args) -> int:
    from warden.llm import LLMError, build_provider

    s = _settings(args)
    try:
        p = build_provider(s)
    except LLMError as exc:
        print(f"LLM misconfigured: {exc}")
        return 1
    tools = [{"name": "report", "description": "Report a number.", "parameters": {"type": "object", "properties": {"value": {"type": "integer"}}, "required": ["value"]}}]
    msgs = [{"role": "system", "content": "You are a test harness. Always answer by calling the provided tool."},
            {"role": "user", "content": "What is 17 + 25? Call `report` with the result."}]
    t0 = time.time()
    try:
        r = p.chat(msgs, tools)
        ok = bool(r.tool_calls) and r.tool_calls[0].arguments.get("value") == 42
        print(f"provider {p.label}: {'OK' if ok else 'UNEXPECTED'} in {time.time() - t0:.1f}s, tool_calls={[(c.name, c.arguments) for c in r.tool_calls]}, text={r.content[:200]!r}, usage={r.usage}")
        if r.tool_calls:  # round-trip a tool result to verify history conversion
            msgs += [r.message, {"role": "tool", "tool_call_id": r.tool_calls[0].id, "content": "recorded"}]
            r2 = p.chat(msgs, tools)
            print(f"follow-up after tool result: OK ({(r2.content or str([c.name for c in r2.tool_calls]))[:120]!r})")
        return 0 if ok else 1
    except LLMError as exc:
        print(f"provider {p.label}: FAILED: {exc}")
        return 1


def cmd_test_email(args) -> int:
    w = _warden(args, attach=False)
    if not w.s.email_configured:
        print("email not configured: set EMAIL_TO and SMTP_HOST (+ SMTP_USER/SMTP_PASSWORD)")
        return 1
    try:
        w.mailer.send_raw(f"[warden][{w.s.hostname}] test email", "If you can read this, Warden can reach you.\n")
        print(f"sent to {', '.join(w.s.email_to)}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {exc}")
        return 1


def cmd_check(args) -> int:
    s = _settings(args)
    ok = True

    def line(good: bool, label: str, detail: str = "") -> None:
        nonlocal ok
        ok = ok and good
        print(f"[{'ok' if good else '!!'}] {label}" + (f": {detail}" if detail else ""))

    line(True, "config file", str(s.env_file) if s.env_file else "none found (using environment)")
    line(s.llm is not None, "LLM config", f"{s.llm.provider}/{s.llm.model} @ {s.llm.base_url}" if s.llm else str(s.llm_error))
    line(os.geteuid() == 0 if hasattr(os, "geteuid") else False, "running as root")
    for b in ("nft", "journalctl", "ss", "systemctl", "ip"):
        line(shutil.which(b) is not None, f"binary {b}")
    line(s.email_configured, "email", f"to {', '.join(s.email_to)} via {s.smtp_host}:{s.smtp_port}" if s.email_configured else "EMAIL_TO / SMTP_HOST missing")
    line(True, "autonomy", s.autonomy)
    line(bool(s.allowlist), "allowlist", ", ".join(s.allowlist) or "empty — add your own IP to WARDEN_ALLOWLIST to be safe")
    line(True, "state dir", str(s.state_dir))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="warden", description="Autonomous 24/7 sysadmin & security agent")
    p.add_argument("--version", action="version", version=f"warden {__version__}")
    p.add_argument("--observe", action="store_true", help="force read-only autonomy for this invocation")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("daemon", help="run forever (systemd entry point)").set_defaults(fn=cmd_daemon)
    sub.add_parser("status", help="overview").set_defaults(fn=cmd_status)
    sp = sub.add_parser("run", help="run a routine now")
    sp.add_argument("name")
    sp.add_argument("--force", action="store_true", help="call the LLM even if no gate fired")
    sp.set_defaults(fn=cmd_run)
    sub.add_parser("onboard", help="(re)run the onboarding host profile").set_defaults(fn=cmd_onboard)
    sp = sub.add_parser("ask", help="give the agent an instruction now")
    sp.add_argument("text", nargs="+")
    sp.set_defaults(fn=cmd_ask)
    sp = sub.add_parser("event", help="raise an event that wakes the daemon (for scripts/monitoring)")
    sp.add_argument("--severity", choices=SEVERITIES, default="medium")
    sp.add_argument("--kind", default="external")
    sp.add_argument("message", nargs="+")
    sp.set_defaults(fn=cmd_event)
    sp = sub.add_parser("incidents", help="list incidents or show one")
    sp.add_argument("id", nargs="?", type=int)
    sp.add_argument("--all", action="store_true")
    sp.set_defaults(fn=cmd_incidents)
    sp = sub.add_parser("resolve", help="mark an incident resolved")
    sp.add_argument("id", type=int)
    sp.add_argument("resolution", nargs="*")
    sp.set_defaults(fn=cmd_resolve)
    sub.add_parser("bans", help="list active bans").set_defaults(fn=cmd_bans)
    sp = sub.add_parser("ban", help="ban an IP/CIDR")
    sp.add_argument("ip")
    sp.add_argument("--minutes", type=int)
    sp.add_argument("--reason", default="manual ban by operator")
    sp.set_defaults(fn=cmd_ban)
    sp = sub.add_parser("unban", help="unban an IP/CIDR")
    sp.add_argument("ip")
    sp.set_defaults(fn=cmd_unban)
    sp = sub.add_parser("routines", help="list / enable / disable routines")
    sp.add_argument("action", nargs="?", choices=["list", "enable", "disable"], default="list")
    sp.add_argument("name", nargs="?")
    sp.set_defaults(fn=cmd_routines)
    sp = sub.add_parser("triggers", help="list / enable / disable / delete triggers")
    sp.add_argument("action", nargs="?", choices=["list", "enable", "disable", "delete"], default="list")
    sp.add_argument("name", nargs="?")
    sp.set_defaults(fn=cmd_triggers)
    sp = sub.add_parser("log", help="audit log of agent actions")
    sp.add_argument("-n", type=int, default=50)
    sp.set_defaults(fn=cmd_log)
    sub.add_parser("test-llm", help="verify the LLM provider (tool calling)").set_defaults(fn=cmd_test_llm)
    sub.add_parser("test-email", help="send a test email").set_defaults(fn=cmd_test_email)
    sub.add_parser("check", help="check configuration and prerequisites").set_defaults(fn=cmd_check)

    args = p.parse_args(argv)
    if args.cmd != "daemon":
        logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    try:
        return args.fn(args) or 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
