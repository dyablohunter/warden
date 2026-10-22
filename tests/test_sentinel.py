import time
import unittest

from tests.helpers import FakeFirewall, make_db, make_settings
from warden.firewall import BanManager
from warden.sentinel import (AUTH_RULES, Sentinel, Window, is_exploit_probe, match_auth_failure, parse_ssh_message,
                             parse_web_line)

PUB = "45.155.205.66"  # public address (documentation ranges count as private in ipaddress)


class ParserTests(unittest.TestCase):
    def test_ssh(self):
        cases = {
            "Failed password for root from 203.0.113.5 port 52811 ssh2": ("fail", "203.0.113.5", "root"),
            "Failed password for invalid user admin from 2001:db8::7 port 1 ssh2": ("fail", "2001:db8::7", "admin"),
            "Invalid user oracle from 198.51.100.9 port 4242": ("invalid", "198.51.100.9", "oracle"),
            "Accepted publickey for alice from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:abc": ("accepted", "192.0.2.10", "alice"),
            "Connection closed by authenticating user root 203.0.113.5 port 3333 [preauth]": ("preauth", "203.0.113.5", "root"),
            "Did not receive identification string from 203.0.113.99 port 1111": ("scan", "203.0.113.99", ""),
            "error: maximum authentication attempts exceeded for root from 203.0.113.5 port 22 ssh2 [preauth]": ("maxauth", "203.0.113.5", "root"),
            "banner exchange: Connection from 203.0.113.44 port 5555: invalid format": ("scan", "203.0.113.44", ""),
        }
        for msg, want in cases.items():
            with self.subTest(msg=msg):
                self.assertEqual(parse_ssh_message(msg), want)
        self.assertIsNone(parse_ssh_message("Server listening on 0.0.0.0 port 22."))
        self.assertIsNone(parse_ssh_message("Invalid user x from not-an-ip port 1"))

    def test_auth_rules(self):
        rules = {r["name"]: r for r in AUTH_RULES}
        cases = [
            ("postgres", '2026-10-22 10:00:00 UTC [123] FATAL:  no pg_hba.conf entry for host "45.1.2.3", user "x", database "y"', "45.1.2.3"),
            ("postgres", "2026-10-22 10:00:00 UTC [123] 45.1.2.4(5555) app@db FATAL:  password authentication failed for user \"app\"", "45.1.2.4"),
            ("mysql", "2026-10-22T10:00:00Z 8 [Note] [MY-010926] Access denied for user 'root'@'45.1.2.5' (using password: YES)", "45.1.2.5"),
            ("smtp", "warning: unknown[45.1.2.6]: SASL LOGIN authentication failed: UGFzc3dvcmQ6", "45.1.2.6"),
            ("imap", "imap-login: Disconnected: Connection closed (auth failed, 3 attempts in 6 secs): user=<a>, method=PLAIN, rip=45.1.2.7, lip=10.0.0.1", "45.1.2.7"),
        ]
        for name, line, ip in cases:
            with self.subTest(rule=name):
                self.assertEqual(match_auth_failure(rules[name], line), ip)
        self.assertIsNone(match_auth_failure(rules["postgres"], "LOG:  checkpoint complete"))

    def test_web(self):
        line = '203.0.113.5 - - [22/Oct/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "sqlmap/1.8"'
        self.assertEqual(parse_web_line(line), ("203.0.113.5", "GET", "/wp-login.php", 404, "sqlmap/1.8"))
        caddy = '{"level":"info","request":{"remote_ip":"10.0.0.1","client_ip":"45.1.1.1","method":"POST","uri":"/login","headers":{"User-Agent":["x"]}},"status":401}'
        self.assertEqual(parse_web_line(caddy), ("45.1.1.1", "POST", "/login", 401, "x"))
        self.assertIsNone(parse_web_line("garbage"))
        for p in ("/../../etc/passwd", "/?q=${jndi:ldap://x}", "/.env", "/.git/config", "/index.php?id=1%20UNION%20SELECT", "/vendor/phpunit/src/Util/PHP/eval-stdin.php"):
            self.assertTrue(is_exploit_probe(p), p)
        for p in ("/", "/about", "/static/app.js", "/api/v1/users?page=2"):
            self.assertFalse(is_exploit_probe(p), p)

    def test_window(self):
        w = Window(10)
        t = time.time()
        self.assertEqual(w.add("a", 1, t - 20), 1)
        self.assertEqual(w.add("a", 1, t), 1)  # old entry expired
        self.assertEqual(w.add("a", 2, t), 3)
        self.assertEqual(w.top(1)[0][0], "a")


class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.s = make_settings(SSH_MAX_FAILURES="5", WARDEN_ALLOWLIST="192.0.2.0/24")
        self.db = make_db()
        self.fw = FakeFirewall()
        self.bans = BanManager(self.s, self.db, self.fw)
        self.bans._own, self.bans._own_ts = {"10.0.0.2"}, time.time() + 9999
        self.woken = 0
        self.sent = Sentinel(self.s, self.db, self.bans, self._wake, stream=False)

    def _wake(self):
        self.woken += 1

    def _kinds(self, notable_only=False):
        return [e["kind"] for e in self.db.pending_events() if not notable_only or e["severity"] != "info"]

    def test_bruteforce_banned_quietly(self):
        for _ in range(5):
            self.sent.handle_ssh("Failed password for root from 203.0.113.5 port 1 ssh2")
        self.assertIn("203.0.113.5", self.fw.banned)
        self.assertEqual(self.fw.banned["203.0.113.5"], self.s.ban_base_minutes * 60)
        self.assertIn("ban", self._kinds())
        self.assertEqual(self._kinds(notable_only=True), [])  # routine ban: no LLM

    def test_journal_dispatch_db_auth(self):
        for _ in range(5):
            self.sent.on_journal({"ident": "postgres", "msg": 'FATAL:  no pg_hba.conf entry for host "45.9.9.9", user "a"', "ts": time.time()})
        self.assertIn("45.9.9.9", self.fw.banned)

    def test_allowlisted_never_banned(self):
        for _ in range(20):
            self.sent.handle_ssh("Failed password for root from 192.0.2.50 port 1 ssh2")
        self.assertNotIn("192.0.2.50", self.fw.banned)

    def test_trusted_after_login(self):
        self.sent.handle_ssh("Accepted publickey for alice from 198.51.100.7 port 1 ssh2: X")
        self.assertIn("ssh_login_new_ip", self._kinds(notable_only=True))
        for _ in range(20):
            self.sent.handle_ssh("Failed password for alice from 198.51.100.7 port 1 ssh2")
        self.assertNotIn("198.51.100.7", self.fw.banned)

    def test_escalation(self):
        self.bans.ban("203.0.113.8", "x", "test")
        ok, msg = self.bans.ban("203.0.113.8", "x", "test")
        self.assertTrue(ok)
        self.assertEqual(self.fw.banned["203.0.113.8"], self.s.ban_base_minutes * 2 * 60)
        self.assertIn("offence #2", msg)

    def test_large_range_refused(self):
        ok, _ = self.bans.ban("10.0.0.0/8", "x", "test")
        self.assertFalse(ok)

    def test_attack_wave(self):
        self.s.attack_wave_bans = 5
        for i in range(5):
            for _ in range(5):
                self.sent.handle_ssh(f"Failed password for root from 45.0.0.{i} port 1 ssh2")
        self.assertIn("attack_wave", self._kinds(notable_only=True))

    def test_web_detectors(self):
        self.s.http_exploit_hits = 2
        for _ in range(2):
            self.sent.handle_web(PUB, "GET", "/.env", 404)
        self.assertIn(PUB, self.fw.banned)
        self.sent.handle_web("45.155.205.67", "GET", "/", 200, "Mozilla/5.0 (compatible; Nmap Scripting Engine)")
        self.assertIn("45.155.205.67", self.fw.banned)
        self.s.http_auth_fail_max = 3
        for _ in range(3):
            self.sent.handle_web("45.155.205.68", "POST", "/api/auth/login", 401)
        self.assertIn("45.155.205.68", self.fw.banned)
        self.s.http_max_req_per_min = 10
        for _ in range(12):
            self.sent.handle_web("45.155.205.69", "GET", "/", 200)
        self.assertIn("45.155.205.69", self.fw.banned)

    def test_private_web_source_not_banned(self):
        self.s.http_max_req_per_min = 5
        for _ in range(10):
            self.sent.handle_web("10.0.0.50", "GET", "/", 200)
        self.assertNotIn("10.0.0.50", self.fw.banned)
        self.assertIn("web_abuse_private_ip", self._kinds(notable_only=True))

    def test_observe_mode_only_suggests(self):
        self.s.autonomy = "observe"
        ok, _ = self.bans.ban("203.0.113.9", "x", "test")
        self.assertFalse(ok)
        self.assertNotIn("203.0.113.9", self.fw.banned)
        self.assertIn("ban_suggested", self._kinds())


if __name__ == "__main__":
    unittest.main()
