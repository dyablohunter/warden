import time
import unittest

from tests.helpers import FakeFirewall, FakeProvider, make_settings
from warden.agent import Agent, Task, compact
from warden.daemon import Daemon, Warden
from warden.firewall import BanManager, build_ruleset, normalize_target

FINISH = ("finish", {"status": "ok", "severity": "info", "title": "all good", "summary": "nothing found", "notify": False})


def _warden(settings, script):
    w = Warden(settings, attach_firewall=False)
    w.firewall = FakeFirewall()
    w.bans = BanManager(settings, w.db, w.firewall)
    w.bans._own_ts = time.time() + 9999
    w.llm = FakeProvider(script)
    w.agent = Agent(settings, w.db, w.llm, w.bans, w.firewall, w.mailer)
    return w


class AgentTests(unittest.TestCase):
    def test_tool_loop_and_finish(self):
        s = make_settings()
        w = _warden(s, [("", [("remember", {"key": "role", "value": "web server"})]), ("", [FINISH])])
        res = w.agent.run(Task("ask", "t", "do it"))
        self.assertEqual(res.status, "ok")
        self.assertEqual(w.db.memory_all()[0]["value"], "web server")
        self.assertEqual(res.steps, 2)
        # second LLM call saw the tool result
        self.assertEqual(w.llm.calls[1][-1]["role"], "tool")
        self.assertEqual(w.db.q("SELECT COUNT(*) n FROM actions")[0]["n"], 2)

    def test_nudge_then_fallback_summary(self):
        s = make_settings()
        w = _warden(s, [("I think all is fine", []), ("still no tool", [])])
        res = w.agent.run(Task("ask", "t", "x"))
        self.assertEqual(res.status, "incomplete")
        self.assertIn("still no tool", res.summary)

    def test_autonomy_gating(self):
        s = make_settings(WARDEN_AUTONOMY="observe")
        w = _warden(s, [("", [("block_ip", {"target": "203.0.113.1", "reason": "x"})]), ("", [FINISH])])
        w.agent.run(Task("ask", "t", "x"))
        self.assertNotIn("203.0.113.1", w.firewall.banned)
        self.assertNotIn("block_ip", [t["name"] for t in w.agent.toolbox.schemas()])
        self.assertIn("suppress_signal", [t["name"] for t in w.agent.toolbox.schemas()])
        self.assertTrue(w.db.q("SELECT result FROM actions WHERE tool='block_ip'")[0]["result"].startswith("BLOCKED"))

    def test_agent_can_arm_trigger_and_routine(self):
        s = make_settings(WARDEN_AUTONOMY="contain")
        script = [
            ("", [("upsert_trigger", {"name": "nginx-down", "kind": "service", "spec": {"unit": "nginx.service"}, "severity": "high"}),
                  ("upsert_routine", {"name": "web_watch", "interval_minutes": 20, "instructions": "check nginx",
                                      "collectors": [{"name": "nginx", "command": "systemctl status nginx --no-pager"}]}),
                  ("upsert_routine", {"name": "evil", "interval_minutes": 20, "collectors": [{"name": "x", "command": "rm -rf /tmp/x"}]}),
                  ("upsert_routine", {"name": "security_pulse", "enabled": False})]),
            ("", [FINISH]),
        ]
        w = _warden(s, script)
        w.seed()
        res = w.agent.run(Task("ask", "t", "x"))
        self.assertIsNotNone(w.db.trigger("nginx-down"))
        self.assertIsNotNone(w.db.routine("web_watch"))
        self.assertIsNone(w.db.routine("evil"))
        self.assertEqual(w.db.routine("security_pulse")["enabled"], 1)
        self.assertTrue(any("armed trigger" in c for c in res.changes))

    def test_compact(self):
        msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        msgs += [{"role": "tool", "tool_call_id": str(i), "content": "x" * 50000} for i in range(10)]
        compact(msgs)
        self.assertLess(sum(len(m["content"]) for m in msgs), 250000)
        self.assertEqual(len(msgs[-1]["content"]), 50000)


class DaemonTests(unittest.TestCase):
    def _daemon(self, script, onboarded=True, **env):
        s = make_settings(**env)
        d = Daemon(s)
        w = _warden(s, script)
        d.db, d.firewall, d.bans, d.llm, d.agent = w.db, w.firewall, w.bans, w.llm, w.agent
        if onboarded:
            d.db.kv_set("onboarded", "1")
        d.last_housekeeping = time.time()  # no network (Cloudflare range refresh) in unit tests
        return d

    def test_routine_sentinel_bans_do_not_wake_llm(self):
        d = self._daemon([])
        d.db.add_event("sentinel", "ban", "info", "banned x", ip="203.0.113.5")
        d.db.x("UPDATE events SET ts=ts-100")
        self.assertFalse(d.tick())
        self.assertEqual(d.llm.calls, [])
        d.db.x("UPDATE events SET ts=ts-4000")
        d.tick()
        self.assertEqual(d.db.pending_events(), [])  # old info events are archived without the LLM

    def test_onboarding_runs_once_first(self):
        d = self._daemon([("", [FINISH])], onboarded=False)
        self.assertTrue(d.tick())
        self.assertEqual(d.db.q("SELECT kind FROM runs")[0]["kind"], "onboarding")
        self.assertTrue(d.db.kv_get("onboarded"))

    def test_trigger_event_routed_to_linked_incident(self):
        d = self._daemon([("", [FINISH])])
        iid = d.db.incident_open("nginx flapping", "medium", "d", time.time() + 99999)
        d.db.trigger_upsert({"name": "nginx-down", "kind": "service", "spec": {"unit": "nginx"}, "incident_id": iid}, "test")
        tid = d.db.trigger("nginx-down")["id"]
        d.db.add_event("trigger", "trigger:nginx-down", "high", "nginx is failed", trigger_id=tid)
        self.assertTrue(d.tick())
        runs = d.db.q("SELECT kind,name FROM runs")
        self.assertEqual((runs[0]["kind"], runs[0]["name"]), ("incident", f"incident-{iid}"))
        self.assertTrue(any("nginx is failed" in n["note"] for n in d.db.incident_notes(iid)))

    def test_event_triage_debounce_and_run(self):
        d = self._daemon([("", [FINISH])])
        d.db.add_event("sentinel", "ban", "medium", "banned x", ip="203.0.113.5")
        self.assertFalse(d.tick())  # debounce window
        d.db.x("UPDATE events SET ts=ts-100")
        self.assertTrue(d.tick())
        self.assertEqual(d.db.pending_events(), [])
        self.assertEqual(d.db.q("SELECT kind FROM runs")[0]["kind"], "events")

    def test_urgent_event_skips_debounce(self):
        d = self._daemon([("", [FINISH])])
        d.db.add_event("trigger", "trigger:ssh-down", "critical", "ssh down")
        self.assertTrue(d.tick())

    def test_own_agent_events_ignored(self):
        d = self._daemon([])
        d.db.add_event("agent:events:triage", "ban", "medium", "x")
        d.db.x("UPDATE events SET ts=ts-100")
        self.assertFalse(d.tick())
        self.assertEqual(d.db.pending_events(), [])

    def test_routine_gating(self):
        d = self._daemon([("", [FINISH]), ("", [FINISH])])
        d.db.routine_upsert({"name": "meta", "interval_minutes": 60, "instructions": "x",
                             "collectors": [{"name": "mem", "command": "@memory", "gate": "changed"}], "next_run": 0}, "test")
        self.assertTrue(d.tick())  # first run: no baseline -> LLM
        r = d.db.routine("meta")
        self.assertEqual(r["last_status"], "ok")
        self.assertGreater(r["next_run"], time.time() + 3000)
        d.db.routine_set("meta", next_run=0)  # unchanged -> quiet, no LLM call
        d.tick()
        self.assertEqual(len(d.llm.calls), 1)
        self.assertEqual(d.db.routine("meta")["last_status"], "quiet")
        d.db.memory_set("role", "db server")  # change -> LLM sees a diff
        d.db.routine_set("meta", next_run=0)
        d.tick()
        self.assertEqual(len(d.llm.calls), 2)
        self.assertIn('<collected_data name="mem" status="CHANGED">\nrole | db server', d.llm.calls[1][1]["content"])

    def test_daily_budget_pauses_routines(self):
        d = self._daemon([("", [FINISH])], WARDEN_DAILY_TOKEN_BUDGET="1000")
        d.db.x("INSERT INTO runs(started,kind,name,status,tokens_in,tokens_out) VALUES(?,?,?,?,?,?)", (time.time(), "routine", "x", "ok", 5000, 10))
        d.db.routine_upsert({"name": "meta", "interval_minutes": 60, "instructions": "x", "gated": 0, "collectors": [{"name": "mem", "command": "@memory"}], "next_run": 0}, "test")
        self.assertTrue(d.tick())
        self.assertEqual(d.db.routine("meta")["last_status"], "budget")
        self.assertEqual(d.llm.calls, [])

    def test_routine_step_limit(self):
        loop = [("", [("list_routines", {})])] * 40
        d = self._daemon(loop, AGENT_MAX_STEPS="30")
        res = d.agent.run(Task("routine", "x", "go"))
        self.assertEqual(res.steps, 15)
        self.assertEqual(res.status, "incomplete")

    def test_incident_follow_up_backoff_and_escalation(self):
        d = self._daemon([("", [FINISH]), ("", [FINISH])], INCIDENT_MAX_CHECKS="2")
        iid = d.db.incident_open("disk filling", "high", "details", time.time() - 1)
        self.assertTrue(d.tick())
        inc = d.db.incident(iid)
        self.assertEqual(inc["checks"], 1)
        self.assertAlmostEqual(inc["next_check"] - time.time(), 30 * 60, delta=60)  # 1st backoff 30m
        d.db.incident_update(iid, next_check=time.time() - 1)
        d.tick()
        self.assertAlmostEqual(d.db.incident(iid)["next_check"] - time.time(), 60 * 60, delta=60)  # then 1h
        d.db.incident_update(iid, next_check=time.time() - 1)
        d.tick()
        self.assertEqual(d.db.incident(iid)["status"], "needs_human")


class FirewallTests(unittest.TestCase):
    def test_ruleset(self):
        r = build_ruleset(100, 500, 20)
        self.assertIn("table inet warden", r)
        self.assertIn("ip saddr @ban4 counter drop", r)
        self.assertIn("ct count over 500", r)
        self.assertIn("policy accept", r)
        self.assertNotIn("ct count", build_ruleset(0, 0, 0))

    def test_normalize(self):
        self.assertEqual(normalize_target("203.0.113.5"), ("203.0.113.5", 4))
        self.assertEqual(normalize_target("203.0.113.5/24"), ("203.0.113.0/24", 4))
        self.assertEqual(normalize_target("2001:db8::1/128"), ("2001:db8::1", 6))
        with self.assertRaises(ValueError):
            normalize_target("0.0.0.0/0")


if __name__ == "__main__":
    unittest.main()
