"""Context compaction/checkpointing, bounded prompt inputs, and rotation of everything Warden stores."""
import os
import tempfile
import time
import unittest
from pathlib import Path

from tests.helpers import FakeFirewall, FakeProvider, make_db, make_settings
from warden import agent as agent_mod
from warden import prompts
from warden.agent import AGED_KEEP, ELIDED, Agent, Task, age
from warden.daemon import prune_backups
from warden.db import Store
from warden.firewall import BanManager
from warden.routines import Section
from warden.tools import MEMORY_MAX_CHARS, ToolContext, t_remember, t_update_incident

FINISH = ("finish", {"status": "ok", "severity": "info", "title": "t", "summary": "s", "notify": False})


def _round(i, size=6000):
    return [{"role": "assistant", "content": "", "tool_calls": [{"id": f"c{i}", "type": "function", "function": {"name": "run_command", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": f"c{i}", "content": "x" * size}]


class ContextTests(unittest.TestCase):
    def test_aging_keeps_last_rounds_full(self):
        msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        for i in range(5):
            msgs += _round(i)
        msgs_small = [dict(m) for m in msgs[:2]] + [dict(m) for m in _round(9, 1000) * 1]
        self.assertEqual(age(msgs_small), 0)  # below the batch threshold: untouched
        age(msgs)
        tools = [m for m in msgs if m["role"] == "tool"]
        self.assertTrue(all(t["content"].endswith(ELIDED) and len(t["content"]) == AGED_KEEP + len(ELIDED) for t in tools[:3]))
        self.assertTrue(all(len(t["content"]) == 6000 for t in tools[3:]))
        before = [m["content"] for m in msgs]
        age(msgs)  # idempotent: the trimmed prefix stays byte-identical (prompt-cache friendly)
        self.assertEqual(before, [m["content"] for m in msgs])

    def test_checkpoint_replaces_history_with_summary(self):
        s = make_settings(AGENT_MAX_STEPS="30")
        db = Store(s.db_path)
        big = Path(tempfile.mkdtemp()) / "big.log"
        big.write_text("line of log output\n" * 3000)
        read = ("", [("read_file", {"path": str(big)})])
        script = [read, read, ("SUMMARY: read the log twice, nothing wrong found yet; next: finish.", []), ("", [FINISH])]
        llm = FakeProvider(script)
        a = Agent(s, db, llm)
        orig_budget = agent_mod.CONTEXT_CHAR_BUDGET
        base = len(prompts.system_prompt(s)) + len("do it")
        agent_mod.CONTEXT_CHAR_BUDGET = base + 30000  # two full 20k outputs exceed it -> checkpoint
        try:
            res = a.run(Task("ask", "t", "do it"))
        finally:
            agent_mod.CONTEXT_CHAR_BUDGET = orig_budget
        self.assertEqual(res.status, "ok")
        self.assertIn("checkpointed", res.summary)
        last_call = llm.calls[-1]
        self.assertEqual(len(last_call), 3)  # system + task + checkpoint summary
        self.assertIn("SUMMARY: read the log twice", last_call[2]["content"])


class BoundedPromptTests(unittest.TestCase):
    def test_memory_cap_and_prompt_block(self):
        db = make_db()
        ctx = ToolContext(settings=make_settings(), db=db)
        for i in range(30):
            out = t_remember(ctx, f"k{i}", "v" * 300)
        self.assertIn("memory is full", out)
        used = sum(len(m["key"]) + len(m["value"]) for m in db.memory_all())
        self.assertLessEqual(used, MEMORY_MAX_CHARS)
        block = prompts._memory_block(db)
        self.assertLessEqual(len(block), prompts.MEMORY_PROMPT_CHARS + 200)

    def test_render_budget(self):
        secs = [Section(f"s{i}", "changed", "y" * 20000, True) for i in range(5)] + [Section("ctx", "context", "z" * 20000, False)]
        out = prompts.render_sections(secs, budget=30000)
        self.assertLess(len(out), 40000)
        self.assertIn('name="ctx"', out)

    def test_incident_summary_rotates_notes(self):
        db = make_db()
        ctx = ToolContext(settings=make_settings(), db=db)
        iid = db.incident_open("t", "high", "initial", time.time())
        for i in range(20):
            t_update_incident(ctx, iid, f"note {i}")
        t_update_incident(ctx, iid, "note final", summary="root cause: X; tried A,B; next: C")
        inc = db.incident(iid)
        self.assertEqual(inc["details"], "root cause: X; tried A,B; next: C")
        p = prompts.incident_prompt(inc, db.incident_notes(iid, limit=100), 12, db)
        self.assertIn("earlier notes omitted", p)
        self.assertNotIn("note 3\n", p)
        self.assertIn("note final", p)


class RotationTests(unittest.TestCase):
    def test_prune_retention_caps_and_suppressions(self):
        db = make_db()
        old = time.time() - 40 * 86400
        db.x("INSERT INTO events(ts,source,kind,severity,details,processed) VALUES(?,?,?,?,?,1)", (old, "s", "ban", "info", "x"))
        db.x("INSERT INTO events(ts,source,kind,severity,details,processed) VALUES(?,?,?,?,?,1)", (time.time() - 8 * 86400, "s", "ban", "info", "x"))
        db.x("INSERT INTO events(ts,source,kind,severity,details,processed) VALUES(?,?,?,?,?,1)", (time.time(), "s", "ban", "high", "keep"))
        iid = db.incident_open("t", "low", "d", 0)
        for i in range(Store.NOTES_PER_INCIDENT + 10):
            db.incident_note(iid, "a", f"n{i}")
        db.routine_upsert({"name": "r", "interval_minutes": 60, "instructions": "x", "suppress": [
            {"collector": "*", "pattern": "old", "expires": time.time() - 1}, {"collector": "*", "pattern": "live", "expires": time.time() + 99}]}, "t")
        orig = dict(Store.ROW_CAPS)
        Store.ROW_CAPS["actions"] = 5
        try:
            for i in range(12):
                db.audit(None, "a", "tool", {}, "r", True)
            deleted = db.prune(90)
        finally:
            Store.ROW_CAPS.clear()
            Store.ROW_CAPS.update(orig)
        self.assertEqual([e["details"] for e in db.q("SELECT details FROM events")], ["keep"])
        self.assertEqual(len(db.incident_notes(iid, limit=1000)), Store.NOTES_PER_INCIDENT)
        self.assertEqual(db.q("SELECT COUNT(*) n FROM actions")[0]["n"], 5)
        self.assertEqual([x["pattern"] for x in db.routine("r")["suppress"]], ["live"])
        self.assertEqual(deleted["suppressions"], 1)

    def test_compact_storage_on_file_db(self):
        s = make_settings()
        db = Store(s.db_path)
        with db.lock:
            db.conn.execute("BEGIN")
            db.conn.executemany("INSERT INTO events(ts,source,kind,severity,details) VALUES(?,?,?,?,?)", [(time.time(), "s", "ban", "info", "x" * 3000)] * 2000)
            db.conn.execute("COMMIT")
        db.x("DELETE FROM events")
        db.compact_storage()  # must not raise; WAL truncated
        self.assertLess(db.size_bytes(), 2_000_000)

    def test_prune_backups(self):
        root = Path(tempfile.mkdtemp())
        for i in range(5):
            d = root / f"2026010{i}"
            d.mkdir()
            (d / "f").write_bytes(b"x" * 1000)
            os.utime(d, (time.time() - (5 - i) * 100, time.time() - (5 - i) * 100))
        old = root / "ancient"
        old.mkdir()
        os.utime(old, (time.time() - 60 * 86400, time.time() - 60 * 86400))
        removed = prune_backups(root, max_age_days=30, max_bytes=2500)
        self.assertEqual(removed, 4)  # ancient by age + 3 oldest by size
        self.assertEqual(sorted(p.name for p in root.iterdir()), ["20260103", "20260104"])


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.s = make_settings()
        self.db = make_db()
        self.fw = FakeFirewall()

        class Edge:
            enabled = True
            blocked, unblocked = {}, []

            def block(self, ip, note):
                self.blocked[ip] = note
                return True, f"rule-{ip}"

            def unblock(self, rule):
                self.unblocked.append(rule)
                return True, ""

        self.edge = Edge()
        self.bans = BanManager(self.s, self.db, self.fw, edge=self.edge)
        self.bans._own_ts = time.time() + 9999

    def test_cloudflare_never_banned(self):
        self.assertEqual(self.bans.proxies.match("104.16.1.1"), "cloudflare")
        self.assertEqual(self.bans.proxies.match("2606:4700::1"), "cloudflare")
        self.assertIsNone(self.bans.proxies.match("45.155.205.66"))
        ok, msg = self.bans.ban("104.16.1.1", "x", "test")
        self.assertFalse(ok)
        self.assertIn("cloudflare proxy", msg)

    def test_edge_ban_lifecycle(self):
        ok, msg = self.bans.ban("45.155.205.66", "credential stuffing", "sentinel", minutes=1, edge=True)
        self.assertTrue(ok)
        self.assertIn("Cloudflare edge", msg)
        self.assertEqual(self.db.ban_get("45.155.205.66")["edge_rule"], "rule-45.155.205.66")
        self.db.x("UPDATE bans SET expires=? WHERE ip=?", (time.time() - 1, "45.155.205.66"))
        self.assertEqual(self.bans.expire_edge(), 1)
        self.assertEqual(self.edge.unblocked, ["rule-45.155.205.66"])
        self.assertIsNone(self.db.ban_get("45.155.205.66")["edge_rule"])

    def test_sentinel_proxy_ip_in_logs(self):
        from warden.sentinel import Sentinel

        sent = Sentinel(self.s, self.db, self.bans, lambda: None, stream=False)
        self.s.http_max_req_per_min = 2
        for _ in range(10):
            sent.handle_web("172.68.1.1", "GET", "/.env", 404, "sqlmap")
        self.assertEqual(self.fw.banned, {})
        self.assertIn("web_logs_show_proxy_ips", [e["kind"] for e in self.db.pending_events()])

    def test_parse_ranges(self):
        from warden.proxies import parse_ranges

        self.assertEqual(parse_ranges("173.245.48.0/20\nbogus\n2400:cb00::/32\n"), ["173.245.48.0/20", "2400:cb00::/32"])


if __name__ == "__main__":
    unittest.main()
