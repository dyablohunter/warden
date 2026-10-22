import json
import os
import tempfile
import unittest

from tests.helpers import make_db
from warden.journal import ErrorTracker, FileTailer, entry_from_json, signature


class JournalTests(unittest.TestCase):
    def test_entry(self):
        e = entry_from_json(json.dumps({"MESSAGE": [104, 105], "SYSLOG_IDENTIFIER": "x", "PRIORITY": "3", "__REALTIME_TIMESTAMP": "1700000000000000", "__CURSOR": "c1"}))
        self.assertEqual((e["msg"], e["ident"], e["prio"], e["ts"], e["cursor"]), ("hi", "x", 3, 1700000000.0, "c1"))
        self.assertIsNone(entry_from_json("{not json"))

    def test_signature_normalises_variables(self):
        a = signature("nginx", "upstream timed out (110) while connecting to 10.0.0.5:8080, request id 3f2a9c1e-1111-2222-3333-444455556666")
        b = signature("nginx", "upstream timed out (110) while connecting to 10.0.0.9:9090, request id 00000000-aaaa-bbbb-cccc-ddddeeeeffff")
        self.assertEqual(a[0], b[0])
        self.assertNotEqual(a[0], signature("nginx", "worker process exited on signal 11")[0])

    def test_tracker(self):
        db = make_db()
        t = ErrorTracker(db)
        e = {"msg": "disk 3 failed", "ident": "app", "unit": "app.service", "prio": 3, "transport": "journal", "ts": 100.0}
        t.add(e)
        t.add({**e, "msg": "disk 7 failed", "ts": 200.0})
        t.add({**e, "prio": 6})  # info: ignored
        t.add({**e, "unit": "warden.service"})  # our own logs: ignored
        self.assertEqual(t.flush(), 1)
        row = db.one("SELECT * FROM log_signatures")
        self.assertEqual((row["count"], row["first_seen"], row["last_seen"]), (2, 100.0, 200.0))
        t.add({**e, "ts": 300.0})
        t.flush()
        self.assertEqual(db.one("SELECT count FROM log_signatures")["count"], 3)

    def test_file_tailer_rotation(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "access.log")
        with open(p, "w") as fh:
            fh.write("old\n")
        t = FileTailer([os.path.join(d, "*.log")])
        self.assertEqual(list(t.read()), [])  # starts at the end
        with open(p, "a") as fh:
            fh.write("a\nb\npartial")
        self.assertEqual([x[1] for x in t.read()], ["a", "b"])
        os.replace(p, p + ".1")  # rotated
        with open(p, "w") as fh:
            fh.write("new\n")
        self.assertEqual([x[1] for x in t.read()], ["new"])


if __name__ == "__main__":
    unittest.main()
