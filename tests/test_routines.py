import time
import unittest

from tests.helpers import make_db, make_settings
from warden import routines


class Ctx:
    def __init__(self):
        self.db = make_db()
        self.settings = make_settings()
        self.sampler = None
        self.firewall = None


class GatingTests(unittest.TestCase):
    def setUp(self):
        self.out = {"a": "line1\nline2", "b": "", "c": "ctx"}
        for k in self.out:
            routines.INTERNAL[f"@test_{k}"] = lambda ctx, since, k=k: self.out[k]
        self.ctx = Ctx()
        self.r = {"name": "t", "interval_minutes": 15, "gated": 1, "suppress": [], "last_outputs": {}, "last_run": None,
                  "collectors": [{"name": "a", "command": "@test_a", "gate": "changed"},
                                 {"name": "b", "command": "@test_b", "gate": "nonempty"},
                                 {"name": "c", "command": "@test_c", "gate": "context"}]}

    def tearDown(self):
        for k in self.out:
            routines.INTERNAL.pop(f"@test_{k}", None)

    def test_first_run_then_quiet_then_diff(self):
        secs = routines.collect(self.r, self.ctx)
        self.assertTrue(routines.needs_llm(self.r, secs))  # no baseline yet
        self.r["last_outputs"] = routines.outputs_for_storage(secs)
        self.assertEqual(set(self.r["last_outputs"]), {"a"})  # only 'changed' collectors are stored
        secs = routines.collect(self.r, self.ctx)
        self.assertFalse(routines.needs_llm(self.r, secs))
        self.out["a"] = "line1\nline2\nline3"
        secs = routines.collect(self.r, self.ctx)
        self.assertTrue(routines.needs_llm(self.r, secs))
        self.assertEqual(secs[0].diff, "+line3")

    def test_nonempty_and_suppress(self):
        self.r["last_outputs"] = {"a": "line1\nline2"}
        self.out["b"] = "sudo: alice : COMMAND=/usr/bin/apt update\nsudo: mallory : COMMAND=/bin/bash"
        secs = routines.collect(self.r, self.ctx)
        self.assertTrue(secs[1].signal)
        self.r["suppress"] = [{"collector": "b", "pattern": r"alice : COMMAND=/usr/bin/apt", "reason": "operator updates"}]
        secs = routines.collect(self.r, self.ctx)
        self.assertTrue(secs[1].signal)
        self.assertEqual(secs[1].suppressed, 1)
        self.r["suppress"].append({"collector": "*", "pattern": r"mallory", "reason": "x", "expires": time.time() - 1})  # expired
        self.assertTrue(routines.collect(self.r, self.ctx)[1].signal)
        self.r["suppress"].append({"collector": "*", "pattern": r"mallory", "reason": "x"})
        self.assertFalse(routines.needs_llm(self.r, routines.collect(self.r, self.ctx)))

    def test_ungated_always_runs(self):
        self.r["gated"] = 0
        self.r["last_outputs"] = {"a": "line1\nline2"}
        self.assertTrue(routines.needs_llm(self.r, routines.collect(self.r, self.ctx)))

    def test_validate(self):
        ok, err = routines.validate_routine({"name": "web", "interval_minutes": 30, "collectors": [
            {"name": "errs", "command": "journalctl -u nginx --since {since} -p err", "gate": "nonempty"}]}, None)
        self.assertIsNone(err)
        _, err = routines.validate_routine({"name": "web", "interval_minutes": 30, "collectors": [{"name": "x", "command": "uptime", "gate": "context"}]}, None)
        self.assertIn("gated routine needs", err)
        _, err = routines.validate_routine({"name": "web", "interval_minutes": 30, "collectors": [{"name": "x", "command": "uptime", "gate": "bogus"}]}, None)
        self.assertIn("gate must be", err)
        _, err = routines.validate_routine({"name": "security_pulse", "protected": 1, "interval_minutes": 2}, {"protected": 1, "collectors": [], "instructions": "x"})
        self.assertIn("within", err)

    def test_defaults_valid(self):
        for r in routines.DEFAULT_ROUTINES:
            with self.subTest(r=r["name"]):
                v, err = routines.validate_routine(r, None)
                self.assertIsNone(err)

    def test_since_substitution(self):
        captured = {}
        orig = routines.util.run
        routines.util.run = lambda cmd, timeout=60: captured.setdefault("cmd", cmd) and routines.util.CmdResult(0, "", "")
        try:
            routines.run_collector({"name": "x", "command": "journalctl -t sudo --since {since}"}, self.ctx, 1700000000.5)
        finally:
            routines.util.run = orig
        self.assertEqual(captured["cmd"], "journalctl -t sudo --since @1700000000")


if __name__ == "__main__":
    unittest.main()
