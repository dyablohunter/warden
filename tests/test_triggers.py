import os
import tempfile
import time
import unittest

from tests.helpers import make_db
from warden import triggers


class TriggerTests(unittest.TestCase):
    def test_validate(self):
        t, err = triggers.validate({"name": "disk", "kind": "metric", "spec": {"metric": "disk_used_pct", "op": ">", "value": "85"}})
        self.assertIsNone(err)
        self.assertNotIn("arg", t["spec"])  # no arg: worst mount
        self.assertEqual(t["spec"]["value"], 85.0)
        self.assertEqual(t["interval_s"], 60)
        _, err = triggers.validate({"name": "x1", "kind": "command", "spec": {"command": "rm -rf /tmp/x", "fire_on": "exit_zero"}})
        self.assertIn("read-only", err)
        _, err = triggers.validate({"name": "BAD NAME", "kind": "file", "spec": {"path": "/x"}})
        self.assertIsNotNone(err)
        t, err = triggers.validate({"name": "fast", "kind": "service", "spec": {"unit": "nginx.service"}, "interval_s": 1, "expires_in_minutes": 10})
        self.assertEqual(t["interval_s"], triggers.MIN_INTERVAL)
        self.assertGreater(t["expires_at"], time.time())
        _, err = triggers.validate({"name": "lg", "kind": "log", "spec": {"pattern": "("}})
        self.assertIn("bad pattern", err)

    def test_compare(self):
        self.assertTrue(triggers.compare(5, ">", 4))
        self.assertFalse(triggers.compare(5, "increase", 0, None))
        self.assertTrue(triggers.compare(6, "increase", 0, 5))

    def test_engine_file_trigger_fires_and_recovers(self):
        db = make_db()
        fd, path = tempfile.mkstemp()
        os.write(fd, b"a")
        os.close(fd)
        t, err = triggers.validate({"name": "watch", "kind": "file", "spec": {"path": path}, "severity": "high", "cooldown_s": 60, "instructions": "check it"})
        self.assertIsNone(err)
        iid = db.incident_open("inc", "high", "d", time.time() + 9999)
        t["incident_id"] = iid
        db.trigger_upsert(t, "test")
        woke = []
        eng = triggers.TriggerEngine(db, on_fire=lambda: woke.append(1))
        now = time.time()
        self.assertEqual(eng.tick(now), 0)  # baseline
        with open(path, "w") as fh:
            fh.write("b")
        self.assertEqual(eng.tick(now + 61), 1)
        ev = db.pending_events()
        self.assertEqual(ev[-1]["kind"], "trigger:watch")
        self.assertIn("check it", ev[-1]["details"])
        self.assertTrue(woke)
        # unchanged afterwards -> recovery event, linked incident woken
        self.assertEqual(eng.tick(now + 122), 1)
        self.assertEqual(db.pending_events()[-1]["kind"], "trigger_recovered:watch")
        self.assertLessEqual(db.incident(iid)["next_check"], now + 122)
        os.unlink(path)

    def test_cooldown_and_once(self):
        db = make_db()
        fd, path = tempfile.mkstemp()
        os.close(fd)
        t, _ = triggers.validate({"name": "once-t", "kind": "file", "spec": {"path": path}, "once": True})
        db.trigger_upsert(t, "test")
        eng = triggers.TriggerEngine(db)
        now = time.time()
        eng.tick(now)
        with open(path, "w") as fh:
            fh.write("x")
        eng.tick(now + 100)
        self.assertEqual(db.trigger("once-t")["enabled"], 0)
        os.unlink(path)

    def test_log_trigger_push_and_recovery(self):
        db = make_db()
        t, err = triggers.validate({"name": "nginx-5xx", "kind": "log", "severity": "high",
                                    "spec": {"unit": "nginx", "pattern": r"upstream timed out", "min_count": 3, "window_s": 60}})
        self.assertIsNone(err)
        db.trigger_upsert(t, "test")
        woke = []
        eng = triggers.TriggerEngine(db, on_fire=lambda: woke.append(1))
        now = time.time()
        e = {"ident": "nginx", "unit": "nginx.service", "prio": 3, "msg": "upstream timed out (110)", "ts": now}
        eng.on_journal({**e, "unit": "other.service"})  # wrong unit
        eng.on_journal(e)
        eng.on_journal({**e, "msg": "all fine"})
        eng.on_journal(e)
        self.assertEqual(db.pending_events(), [])
        eng.on_journal(e)
        self.assertEqual(db.pending_events()[-1]["kind"], "trigger:nginx-5xx")
        self.assertTrue(woke)
        eng.on_journal(e)  # cooldown: no second event
        self.assertEqual(len(db.pending_events()), 1)
        eng.tick(now + 120)  # window drained -> recovery
        self.assertEqual(db.pending_events()[-1]["kind"], "trigger_recovered:nginx-5xx")

    def test_metric_from_sampler(self):
        class Stub:
            def value(self, metric, arg=None):
                return ({"syncookies_sent_ps": 50.0}.get(metric), metric)

        t, _ = triggers.validate({"name": "syn", "kind": "metric", "spec": {"metric": "syncookies_sent_ps", "op": ">", "value": 5}})
        hit, value, detail, _ = triggers.evaluate({**t, "state": {}}, Stub())
        self.assertTrue(hit)
        _, err = triggers.validate({"name": "pc", "kind": "metric", "spec": {"metric": "port_conns", "op": ">", "value": 90}})
        self.assertIn("port", err)

    def test_service_verdict(self):
        self.assertFalse(triggers.service_verdict("a", "ActiveState=active\nType=simple\nLoadState=loaded")[0])
        self.assertTrue(triggers.service_verdict("a", "ActiveState=failed\nType=simple\nLoadState=loaded")[0])
        self.assertTrue(triggers.service_verdict("a", "ActiveState=activating\nType=notify\nLoadState=loaded")[0])
        self.assertFalse(triggers.service_verdict("a", "ActiveState=inactive\nType=oneshot\nLoadState=loaded")[0])
        self.assertTrue(triggers.service_verdict("a", "ActiveState=failed\nType=oneshot\nLoadState=loaded")[0])
        self.assertEqual(triggers.service_verdict("a", "ActiveState=inactive\nType=\nLoadState=not-found")[1], "not-found")

    def test_expiry(self):
        db = make_db()
        t, _ = triggers.validate({"name": "exp", "kind": "file", "spec": {"path": "/nonexistent"}})
        t["expires_at"] = time.time() - 1
        db.trigger_upsert(t, "test")
        triggers.TriggerEngine(db).tick()
        self.assertEqual(db.trigger("exp")["enabled"], 0)


if __name__ == "__main__":
    unittest.main()
