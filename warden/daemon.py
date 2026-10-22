"""Main loop: sleep until something is due, run it, report, repeat.

Priority each tick: notable events (triage) > incident follow-ups > onboarding (once) > routines.
Routines collect data without the LLM and only call it when a gate fires.
"""
from __future__ import annotations

import logging
import os
import shutil
import signal
import threading
import time

from warden import __version__, prompts, util
from warden.agent import Agent, AgentResult, Task
from warden.config import apply_overrides, severity_rank
from warden.db import Store
from warden.firewall import TABLE, BanManager, Firewall, apply_sysctl_hardening
from warden.journal import FIELDS, ErrorTracker
from warden.llm import LLMError, build_provider
from warden.metrics import Sampler
from warden.notify import Mailer
from warden.routines import DEFAULT_ROUTINES, ONBOARDING_COLLECTORS, collect, needs_llm, outputs_for_storage
from warden.sentinel import Sentinel
from warden.triggers import default_triggers, validate as validate_trigger

log = logging.getLogger("warden")

TRIAGE_DEBOUNCE = 45  # let related events accumulate
TRIAGE_MIN_GAP = 300  # minimum seconds between triage runs (unless high/critical)
MAX_SLEEP = 300
DEFAULTS_VERSION = "2"  # bump when built-in routines/triggers change; untouched built-ins get upgraded
RETIRED_ROUTINES = {"self_review", "hardening_audit"}  # merged into weekly_review


def prune_backups(root, max_age_days: int, max_bytes: int) -> int:
    """Delete config backups older than max_age_days, then oldest-first until the total is under max_bytes."""
    if not root.is_dir():
        return 0
    dirs = []
    for d in root.iterdir():
        if d.is_dir():
            size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
            dirs.append((d.stat().st_mtime, size, d))
    dirs.sort()
    total, removed = sum(s for _, s, _ in dirs), 0
    cutoff = time.time() - max_age_days * 86400
    for mtime, size, d in dirs:
        if mtime < cutoff or total > max_bytes:
            shutil.rmtree(d, ignore_errors=True)
            total -= size
            removed += 1
    return removed


def effective_tokens(tin: int, cached: int, tout: int) -> float:
    """Budget accounting: cached prompt tokens cost ~10% of fresh ones on DeepSeek/OpenAI/Anthropic."""
    return (tin or 0) - 0.9 * (cached or 0) + (tout or 0)


class Warden:
    """Everything wired together. Used by the daemon and by one-shot CLI commands."""

    def __init__(self, settings, attach_firewall: bool = True):
        self.s = self.settings = settings
        self.db = Store(settings.db_path)
        apply_overrides(settings, self.db.kv_prefix("tune."))
        self.firewall = Firewall(settings)
        if attach_firewall and self.firewall.available:
            self.firewall.ready = util.run(["nft", "list", "table", "inet", TABLE], timeout=10).ok
        self.bans = BanManager(settings, self.db, self.firewall)
        self.mailer = Mailer(settings, self.db)
        self.sampler = Sampler()
        self.tracker = ErrorTracker(self.db)
        self.llm = None
        self.llm_error = None
        try:
            self.llm = build_provider(settings)
        except LLMError as exc:
            self.llm_error = str(exc)
        self.agent = Agent(settings, self.db, self.llm, self.bans, self.firewall, self.mailer, self.sampler) if self.llm else None
        self.wake_event = threading.Event()

    def wake(self) -> None:
        self.wake_event.set()

    # ── seeding ───────────────────────────────────────────────────────────
    def seed(self) -> None:
        now = time.time()
        upgrade = self.db.kv_get("defaults_version") != DEFAULTS_VERSION
        for name in RETIRED_ROUTINES:
            r = self.db.routine(name)
            if r and r["builtin"]:
                self.db.routine_delete(name)
        for i, r in enumerate(DEFAULT_ROUTINES):
            cur = self.db.routine(r["name"])
            if not cur:
                self.db.routine_upsert({**r, "builtin": 1, "next_run": now + 120 + i * 90}, "seed")
            elif upgrade and cur["builtin"] and cur["updated_by"] == "seed":
                self.db.routine_upsert({**r, "builtin": 1, "suppress": cur["suppress"]}, "seed")
        for t in default_triggers(self.s):
            cur = self.db.trigger(t["name"])
            if cur and not (upgrade and cur["builtin"] and cur["created_by"] == "seed"):
                continue
            v, err = validate_trigger(t)
            if v:
                self.db.trigger_upsert({**v, "builtin": 1}, "seed")
            else:
                log.warning("default trigger %s invalid: %s", t["name"], err)
        self.db.kv_set("defaults_version", DEFAULTS_VERSION)

    def seed_error_baseline(self) -> None:
        """Treat the last 7 days of errors as already known, so only genuinely new ones wake the LLM."""
        if self.db.kv_get("errors_seeded"):
            return
        res = util.run(["journalctl", "-p", "err", "--since", "-7d", "-o", "json", "--no-pager", f"--output-fields={FIELDS}"], timeout=120)
        n = self.tracker.seed(res.stdout.splitlines()[-50000:])
        # backdate so the first health_pulse doesn't treat the baseline as new
        self.db.x("UPDATE log_signatures SET first_seen=MIN(first_seen, ?)", (time.time() - 86400,))
        self.db.kv_set("errors_seeded", str(time.time()))
        log.info("error baseline: %d known signatures", n)

    # ── job runners ───────────────────────────────────────────────────────
    def _run_agent(self, task: Task) -> AgentResult | None:
        if not self.agent:
            log.error("LLM unavailable (%s); skipping %s", self.llm_error, task.name)
            return None
        result = self.agent.run(task)
        self._llm_health(result)
        self.report(task, result)
        return result

    def run_routine(self, name: str, force: bool = False) -> AgentResult | None:
        r = self.db.routine(name)
        if not r:
            raise KeyError(name)
        started = time.time()
        sections = collect(r, self, started)
        interval = r["interval_minutes"] * 60
        if not force and not needs_llm(r, sections):
            self.db.routine_set(name, last_run=started, next_run=started + interval, last_status="quiet", last_outputs=outputs_for_storage(sections))
            log.info("routine %s: quiet (no gate fired), LLM not called", name)
            return None
        if self.over_budget():
            self.db.routine_set(name, next_run=started + interval, last_status="budget")
            log.warning("routine %s skipped: daily token budget exhausted", name)
            return None
        result = self._run_agent(Task("routine", name, prompts.routine_prompt(r, sections, self.db)))
        r2 = self.db.routine(name)
        if not r2:  # the agent deleted it
            return result
        if result and not result.error:
            self.db.routine_set(name, last_run=started, next_run=time.time() + r2["interval_minutes"] * 60, last_status=result.status,
                                last_summary=result.summary[:2000], last_outputs=outputs_for_storage(sections))
        else:  # keep last_run so the next attempt re-covers the same window and diffs
            self.db.routine_set(name, last_status="error", next_run=time.time() + min(r2["interval_minutes"], 15) * 60)
        return result

    def run_onboarding(self) -> AgentResult | None:
        pseudo = {"name": "onboarding", "interval_minutes": 60, "collectors": ONBOARDING_COLLECTORS, "last_outputs": {}}
        sections = collect(pseudo, self)
        result = self._run_agent(Task("onboarding", "onboarding", prompts.onboarding_prompt(sections, self.db)))
        if result and not result.error:
            self.db.kv_set("onboarded", str(time.time()))
        else:
            self.db.kv_set("onboarding_retry", str(time.time() + 3600))
        return result

    def notable_pending(self) -> list[dict]:
        return [e for e in self.db.pending_events() if e["severity"] != "info" and not (e["source"] or "").startswith("agent:")]

    def run_events(self) -> AgentResult | None:
        pending = self.notable_pending()
        if not pending:
            return None
        ids = [e["id"] for e in pending]
        actions = self.db.q("SELECT ts,tool,args FROM actions WHERE ts>? AND tool NOT IN ('read_file','run_command','list_incidents','list_routines','list_triggers','list_blocked','finish','test_trigger') ORDER BY ts DESC LIMIT 30", (time.time() - 7200,))
        if not self.agent:
            self.db.mark_events(ids)
            worst = max(pending, key=lambda e: severity_rank(e["severity"]))["severity"]
            body = "LLM unavailable, raw events:\n\n" + "\n".join(f"{util.iso(e['ts'])} [{e['severity']}] {e['kind']} {e['details'][:300]}" for e in pending[:200])
            self.mailer.notify(f"{len(pending)} security events (LLM unavailable)", body, worst)
            return None
        result = self._run_agent(Task("events", "triage", prompts.events_prompt(pending, actions, self.db)))
        self.db.mark_events(ids)
        self.db.kv_set("last_triage", str(time.time()))
        return result

    def route_incident_events(self) -> None:
        """Trigger events linked to an incident wake that incident's follow-up instead of a generic triage."""
        for e in self.db.pending_events():
            if not e["trigger_id"] or e["severity"] == "info":
                continue
            t = self.db.one("SELECT incident_id FROM triggers WHERE id=?", (e["trigger_id"],))
            inc = self.db.incident(t["incident_id"]) if t and t["incident_id"] else None
            if inc and inc["status"] != "resolved":
                self.db.incident_note(inc["id"], "trigger", e["details"][:2000])
                self.db.incident_update(inc["id"], next_check=time.time(), status="open" if inc["status"] == "needs_human" else inc["status"])
                self.db.mark_events([e["id"]])

    def run_incident(self, inc: dict) -> AgentResult | None:
        checks = inc["checks"] + 1
        self.db.incident_update(inc["id"], checks=checks)
        if checks > self.s.incident_max_checks:
            self.db.incident_update(inc["id"], status="needs_human", next_check=None)
            notes = self.db.incident_notes(inc["id"], limit=10)
            body = (f"Incident #{inc['id']} '{inc['title']}' was not resolved after {self.s.incident_max_checks} automated attempts and needs you.\n\n"
                    f"Details:\n{inc['details']}\n\nLatest notes:\n" + "\n".join(f"- {util.iso(n['ts'])} {n['note'][:600]}" for n in notes))
            self.mailer.notify(f"Incident #{inc['id']} needs a human: {inc['title']}", body, "high")
            return None
        before = inc["next_check"]
        task = Task("incident", f"incident-{inc['id']}", prompts.incident_prompt(inc, self.db.incident_notes(inc["id"]), self.s.incident_max_checks, self.db), inc["id"])
        result = self._run_agent(task)
        after = self.db.incident(inc["id"])
        if after and after["status"] in ("open", "monitoring") and (not after["next_check"] or after["next_check"] == before or after["next_check"] <= time.time()):
            # exponential backoff: 30m, 1h, 2h, 4h ... 24h; triggers linked to the incident wake it earlier
            minutes = 15 if result is None or result.error else min(1440, 30 * 2 ** (checks - 1))
            if after["status"] == "monitoring":
                minutes = max(minutes, 120)
            self.db.incident_update(inc["id"], next_check=time.time() + minutes * 60)
        return result

    def ask(self, text: str) -> AgentResult | None:
        return self._run_agent(Task("ask", "operator", prompts.ask_prompt(text, self.db)))

    # ── reporting ─────────────────────────────────────────────────────────
    def report(self, task: Task, result: AgentResult) -> None:
        system_changes = [c for c in result.changes if c.startswith(("ran ", "wrote ", "banned ", "unbanned ", "tuned "))]
        notify = result.notify or bool(system_changes and task.kind != "ask")
        severity = result.severity
        if system_changes and severity_rank(severity) < severity_rank("medium") and task.kind != "events":
            severity = "medium"
        if not notify:
            return
        body = result.summary.strip()
        if result.changes:
            body += "\n\nActions taken by Warden:\n" + "\n".join(f"- {c}" for c in result.changes)
        active = self.db.incidents_active()
        if active:
            body += "\n\nActive incidents:\n" + "\n".join(f"- #{i['id']} [{i['status']}/{i['severity']}] {i['title']}" for i in active)
        body += (f"\n\n(task: {task.kind}/{task.name}, status: {result.status}, steps: {result.steps}, "
                 f"tokens in/cached/out: {result.tokens_in}/{result.tokens_cached}/{result.tokens_out})")
        status = self.mailer.notify(result.title or task.name, body, severity, force=task.kind == "ask")
        log.info("report for %s: %s", task.name, status)

    def tokens_last_24h(self) -> float:
        r = self.db.one("SELECT COALESCE(SUM(tokens_in),0) tin, COALESCE(SUM(tokens_cached),0) cached, COALESCE(SUM(tokens_out),0) tout FROM runs WHERE started>?",
                        (time.time() - 86400,))
        return effective_tokens(r["tin"], r["cached"], r["tout"]) if r else 0.0

    def over_budget(self) -> bool:
        if not self.s.daily_token_budget:
            return False
        used = self.tokens_last_24h()
        if used < self.s.daily_token_budget:
            return False
        if time.time() - float(self.db.kv_get("budget_mailed") or 0) > 86400:
            self.db.kv_set("budget_mailed", str(time.time()))
            self.mailer.notify("Daily LLM token budget exhausted",
                               f"{used:,.0f} effective tokens used in the last 24h (budget {self.s.daily_token_budget:,}). Scheduled routines are paused "
                               "until usage drops; the sentinel, triggers, attack triage and incident follow-ups continue.\n"
                               "Raise WARDEN_DAILY_TOKEN_BUDGET, or ask Warden to suppress whatever keeps waking it.", "medium")
        return True

    def _llm_health(self, result: AgentResult) -> None:
        if result.error and result.error.startswith("LLM error"):
            since = float(self.db.kv_get("llm_fail_since") or 0)
            if not since:
                self.db.kv_set("llm_fail_since", str(time.time()))
            last_mail = float(self.db.kv_get("llm_fail_mailed") or 0)
            if since and time.time() - since > 1800 and time.time() - last_mail > 6 * 3600:
                self.mailer.notify("LLM provider failing", f"Warden cannot reach its LLM since {util.iso(since)}.\nLast error: {result.error[:1500]}\n"
                                   "The sentinel (bans, triggers) keeps working; analysis is paused.", "high")
                self.db.kv_set("llm_fail_mailed", str(time.time()))
        else:
            self.db.kv_set("llm_fail_since", "0")


class Daemon(Warden):
    def __init__(self, settings):
        super().__init__(settings, attach_firewall=False)
        self.stopping = False
        self.sentinel: Sentinel | None = None
        self.last_housekeeping = 0.0

    def _signals(self) -> None:
        def stop(signum, _frame):
            log.info("signal %s: stopping", signum)
            self.stopping = True
            self.wake()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGUSR1, lambda *_: self.wake())
        signal.signal(signal.SIGHUP, lambda *_: self.wake())

    def start(self) -> int:
        if os.geteuid() != 0:
            log.warning("not running as root: firewall, most collectors and fixes will fail")
        self.s.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.s.state_dir, 0o700)
        self.s.pid_path.write_text(str(os.getpid()))
        self._signals()
        self.seed()
        self.seed_error_baseline()
        fw_status = "disabled (observe mode)"
        if self.s.autonomy_at_least("contain"):
            if self.firewall.setup():
                # trusted proxies (Cloudflare) skip our per-source limits: thousands of visitors share their addresses
                self.firewall.set_allowlist(self.s.allowlist + self.bans.proxies.cidrs())
                fw_status = f"active, {self.bans.restore()} bans restored"
            else:
                fw_status = f"FAILED: {self.firewall.last_error}"
        sysctl_status = apply_sysctl_hardening() if self.s.harden_sysctl and self.s.autonomy_at_least("full") else "skipped"
        if self.s.sentinel_enabled:
            self.sentinel = Sentinel(self.s, self.db, self.bans, self.wake, sampler=self.sampler, tracker=self.tracker)
            self.sentinel.start()
        summary = (f"Warden {__version__} online on {self.s.hostname}\n"
                   f"LLM: {self.llm.label if self.llm else 'UNAVAILABLE: ' + str(self.llm_error)}\n"
                   f"Autonomy: {self.s.autonomy}\nFirewall: {fw_status}\nSysctl hardening: {sysctl_status}\n"
                   f"Sentinel: {'on' if self.sentinel else 'off'}\nRoutines: {', '.join(r['name'] + '/' + str(r['interval_minutes']) + 'm' for r in self.db.routines(True))}\n"
                   f"Triggers: {len(self.db.triggers(True))} enabled\nActive incidents: {len(self.db.incidents_active())}\n"
                   f"Allowlist: {', '.join(self.s.allowlist) or '(none)'}")
        log.info(summary.replace("\n", " | "))
        if self.s.email_on_start:
            self.mailer.notify("Warden started", summary, "high" if not self.llm or fw_status.startswith("FAILED") else "info", force=True)
        try:
            self.loop()
        finally:
            if self.sentinel:
                self.sentinel.stop()
            try:
                self.s.pid_path.unlink()
            except OSError:
                pass
        log.info("stopped")
        return 0

    def loop(self) -> None:
        while not self.stopping:
            try:
                ran = self.tick()
            except Exception:  # noqa: BLE001 — the daemon must survive anything
                log.exception("tick failed")
                ran = False
                self.wake_event.wait(30)
            if ran or self.stopping:
                continue
            self.wake_event.wait(self.seconds_until_next())
            self.wake_event.clear()

    def tick(self) -> bool:
        now = time.time()
        if now - self.last_housekeeping > 3600:
            self.housekeeping()
        self.mailer.flush_digest()
        self.bans.expire_edge()

        # 1. notable events (attacks, anomalies, triggers, new logins)
        self.route_incident_events()
        pending = self.db.pending_events()
        own_or_info = [e["id"] for e in pending if (e["source"] or "").startswith("agent:") or (e["severity"] == "info" and now - e["ts"] > 3600)]
        if own_or_info:
            self.db.mark_events(own_or_info)
        notable = self.notable_pending()
        if notable:
            urgent = any(severity_rank(e["severity"]) >= severity_rank("high") for e in notable)
            oldest = min(e["ts"] for e in notable)
            last = float(self.db.kv_get("last_triage") or 0)
            if (urgent or now - oldest >= TRIAGE_DEBOUNCE) and (urgent or now - last >= TRIAGE_MIN_GAP):
                self.run_events()
                return True

        # 2. incident follow-ups (fresh clock: routing above may have just made one due)
        now = time.time()
        due = [i for i in self.db.incidents_active() if i["status"] in ("open", "monitoring") and i["next_check"] and i["next_check"] <= now]
        if due:
            self.run_incident(min(due, key=lambda i: i["next_check"]))
            return True

        # 3. onboarding, once
        if self.agent and not self.db.kv_get("onboarded") and float(self.db.kv_get("onboarding_retry") or 0) <= now:
            self.run_onboarding()
            return True

        # 4. routines (collect cheaply; LLM only if a gate fires)
        due_r = [r for r in self.db.routines(enabled_only=True) if (r["next_run"] or 0) <= now]
        if due_r:
            self.run_routine(min(due_r, key=lambda r: r["next_run"] or 0)["name"])
            return True
        return False

    def seconds_until_next(self) -> float:
        now = time.time()
        cands = [now + MAX_SLEEP]
        cands += [r["next_run"] for r in self.db.routines(enabled_only=True) if r["next_run"]]
        cands += [i["next_check"] for i in self.db.incidents_active() if i["next_check"] and i["status"] in ("open", "monitoring")]
        pending = self.notable_pending()
        if pending:
            last = float(self.db.kv_get("last_triage") or 0)
            cands.append(max(min(e["ts"] for e in pending) + TRIAGE_DEBOUNCE, last + TRIAGE_MIN_GAP))
        return max(1.0, min(cands) - now)

    def housekeeping(self) -> None:
        """Hourly: rotate every kind of data Warden keeps, so storage and prompts stay bounded forever."""
        self.last_housekeeping = time.time()
        deleted = self.db.prune(self.s.retention_days)
        self.db.bans_active()
        if deleted:
            log.info("rotation: %s", ", ".join(f"{k}={v}" for k, v in sorted(deleted.items())))
        removed = prune_backups(self.s.backup_dir, max_age_days=30, max_bytes=self.s.backup_max_mb * 1024 * 1024)
        if removed:
            log.info("rotation: removed %d old config backups", removed)
        if time.time() - float(self.db.kv_get("last_compact") or 0) > 86400:
            self.db.compact_storage()
            self.db.kv_set("last_compact", str(time.time()))
        status = self.bans.proxies.refresh()
        if status.startswith("refreshed") and self.firewall.ready:
            self.firewall.set_allowlist(self.s.allowlist + self.bans.proxies.cidrs())
            log.info("trusted proxies %s", status)
