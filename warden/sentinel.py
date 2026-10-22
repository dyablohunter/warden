"""Sentinel: the fast, deterministic defence layer (no LLM).

Real time (journald stream):  SSH / database / mail auth failures -> ban; log triggers; error signatures
Every tick (~10s, /proc only): metrics sample, per-IP connection floods, baseline anomalies (distributed
                               floods), attack waves, web log tail (floods, scanners, credential stuffing,
                               exploit probes), metric/command/file/service/port triggers
Routine bans are logged as `info` (no LLM). Only notable things become events that wake the agent.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter, defaultdict, deque
from urllib.parse import unquote

from warden.journal import FileTailer, JournalStream
from warden.metrics import AnomalyDetector, Sampler
from warden.triggers import TriggerEngine

log = logging.getLogger("warden.sentinel")

_IPV = r"[0-9a-fA-F:.]+"
_IP = rf"(?P<ip>{_IPV})"
SSH_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("accepted", re.compile(r"^Accepted (?:password|publickey|keyboard-interactive/pam|hostbased|gssapi-with-mic) for (?P<user>\S+) from " + _IP)),
    ("fail", re.compile(r"^Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S+) from " + _IP)),
    ("invalid", re.compile(r"^Invalid user (?P<user>\S*) from " + _IP)),
    ("maxauth", re.compile(r"^(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from " + _IP)),
    ("preauth", re.compile(r"^(?:Connection closed|Disconnected) by (?:authenticating|invalid) user (?P<user>\S*) " + _IP + r" port \d+ \[preauth\]")),
    ("scan", re.compile(r"^(?:Did not receive identification string from " + _IP + r"|(?:error: )?kex_exchange_identification: .*|banner exchange: Connection from " + rf"(?P<ip2>{_IPV})" + r" port \d+: invalid format)")),
    ("scan", re.compile(r"^(?:error: )?Protocol major versions differ.* from " + _IP)),
    ("scan", re.compile(r"^Unable to negotiate with " + _IP + r" port \d+: no matching")),
]
SSH_WEIGHTS = {"fail": 1.0, "invalid": 1.0, "maxauth": 2.0, "preauth": 0.5, "scan": 0.5}
SSH_IDENTS = {"sshd", "sshd-session"}

# Built-in "jails" for other network services: journald identifiers and/or log files, regex with (?P<ip>)
AUTH_RULES: list[dict] = [
    {"name": "postgres", "idents": {"postgres", "postgresql"}, "files": ["/var/log/postgresql/*.log"], "patterns": [
        re.compile(r'no pg_hba\.conf entry for host "(?P<ip>[^"]+)"'),
        # client IP only appears if log_line_prefix contains %h/%r: require the failure, then take the first valid IP on the line
        (re.compile(r"FATAL:\s+(?:password|md5|scram-sha-256|ident|ldap|pam) authentication failed"), None),
    ]},
    {"name": "mysql", "idents": {"mysqld", "mariadbd", "mysql"}, "files": ["/var/log/mysql/error.log", "/var/log/mysql/mysql.log"], "patterns": [
        re.compile(r"Access denied for user '[^']*'@'(?P<ip>[^']+)'"),
    ]},
    {"name": "smtp", "idents": {"postfix/smtpd", "postfix/submission/smtpd", "postfix/smtps/smtpd"}, "files": [], "patterns": [
        re.compile(r"warning: \S+\[(?P<ip>[^\]]+)\]: SASL \S+ authentication failed"),
    ]},
    {"name": "imap", "idents": {"dovecot"}, "files": [], "patterns": [
        re.compile(rf"auth failed.*?rip=(?P<ip>{_IPV})"),
    ]},
]

WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]{3,10}|-) ?(?P<path>[^ "]*)[^"]*" (?P<status>\d{3}) \S+'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
EXPLOIT = re.compile(
    r"(?:\.\./\.\./|/etc/passwd|/proc/self/environ|\$\{jndi:|<script|union(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?select|/\.env(?:$|\?|\.)|/\.git/"
    r"|wp-config\.php|phpunit/.*eval-stdin|/cgi-bin/.*(?:sh|bash)|/vendor/phpunit|/boaform|/HNAP1|/shell\?|cmd=|"
    r"\bbase64_decode\b|/actuator/(?:env|heapdump)|/\.aws/credentials|/server-status|/owa/auth/|/solr/admin|"
    r"%00|\bsleep\(\d+\)|/manager/html|/console/login|/invoker/|/druid/|/autodiscover/|;\s*(?:wget|curl)\s|\bwaitfor\s+delay\b)",
    re.I,
)
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|gobuster|ffuf|feroxbuster|acunetix|netsparker|openvas|hydra|joomscan|whatweb|jaeles|xray/", re.I)
AUTH_PATH = re.compile(r"login|signin|sign-in|auth|token|session|password|wp-login|xmlrpc|/admin", re.I)


# ── parsers (pure) ─────────────────────────────────────────────────────────
def _valid_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    ip = ip.strip("[]")
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def parse_ssh_message(msg: str) -> tuple[str, str, str] | None:
    """-> (kind, ip, user) for an sshd log message, else None."""
    for kind, rx in SSH_PATTERNS:
        m = rx.search(msg)
        if m:
            ip = _valid_ip(m.groupdict().get("ip") or m.groupdict().get("ip2"))
            return (kind, ip, m.groupdict().get("user") or "") if ip else None
    return None


IP_CANDIDATE = re.compile(r"(?<![\w:.])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.])")


def match_auth_failure(rule: dict, line: str) -> str | None:
    for p in rule["patterns"]:
        if isinstance(p, tuple):  # (required failure phrase, None): scan the line for the first valid IP
            if p[0].search(line):
                for cand in IP_CANDIDATE.findall(line):
                    ip = _valid_ip(cand)
                    if ip:
                        return ip
            continue
        m = p.search(line)
        if m:
            return _valid_ip(m.group("ip"))
    return None


def parse_web_line(line: str) -> tuple[str, str, str, int, str] | None:
    """Combined log format or JSON (Caddy / custom nginx json) -> (ip, method, path, status, user_agent)."""
    line = line.strip()
    if line.startswith("{"):
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            return None
        req = o.get("request") if isinstance(o.get("request"), dict) else {}
        ip = req.get("client_ip") or req.get("remote_ip") or o.get("remote_addr") or o.get("client_ip") or o.get("ip")
        hdrs = req.get("headers") or {}
        ua = hdrs.get("User-Agent") or o.get("http_user_agent") or o.get("user_agent") or ""
        if isinstance(ua, list):
            ua = ua[0] if ua else ""
        path = req.get("uri") or o.get("request_uri") or o.get("uri") or o.get("path") or ""
        method = req.get("method") or o.get("request_method") or o.get("method") or "-"
        try:
            status = int(o.get("status"))
        except (TypeError, ValueError):
            return None
        ip = _valid_ip(str(ip) if ip else None)
        return (ip, method, path, status, ua) if ip else None
    m = WEB_LINE.match(line)
    if not m:
        return None
    ip = _valid_ip(m["ip"])
    return (ip, m["method"], m["path"], int(m["status"]), m["ua"] or "") if ip else None


def is_exploit_probe(path: str) -> bool:
    return bool(EXPLOIT.search(path) or EXPLOIT.search(unquote(path)))


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return True


class Window:
    """Thread-safe sliding-window weighted counter per key."""

    def __init__(self, seconds: int):
        self.seconds = seconds
        self.data: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def add(self, key: str, weight: float = 1.0, ts: float | None = None) -> float:
        ts = ts or time.time()
        with self.lock:
            dq = self.data[key]
            dq.append((ts, weight))
            cutoff = ts - self.seconds
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            return sum(w for _, w in dq)

    def reset(self, key: str) -> None:
        with self.lock:
            self.data.pop(key, None)

    def top(self, n: int = 5) -> list[tuple[str, float]]:
        with self.lock:
            return sorted(((k, sum(w for _, w in dq)) for k, dq in self.data.items()), key=lambda x: -x[1])[:n]

    def gc(self) -> None:
        cutoff = time.time() - self.seconds
        with self.lock:
            for k in [k for k, dq in self.data.items() if not dq or dq[-1][0] < cutoff]:
                del self.data[k]


class Sentinel(threading.Thread):
    def __init__(self, settings, db, bans, wake, sampler: Sampler | None = None, tracker=None, stream: bool = True):
        super().__init__(name="sentinel", daemon=True)
        self.s, self.db, self.bans, self.wake = settings, db, bans, wake
        self.stop_event = threading.Event()
        self.sampler = sampler or Sampler()
        self.tracker = tracker
        self.triggers = TriggerEngine(db, on_fire=wake, sampler=self.sampler)
        self.anomaly = AnomalyDetector()
        try:
            self.anomaly.load(json.loads(db.kv_get("anomaly.baselines") or "{}"))
        except json.JSONDecodeError:
            pass
        self.auth = Window(settings.ssh_window)
        self.http_req = Window(60)
        self.http_4xx = Window(60)
        self.http_auth = Window(600)
        self.http_exploit = Window(600)
        self.recent_bans: deque = deque()
        self.recently_banned: dict[str, float] = {}
        self.noted: dict[str, float] = {}  # dedupe for notable events
        self.web = FileTailer(settings.web_access_logs)
        self.auth_files = FileTailer([f for r in AUTH_RULES for f in r["files"]])
        self.file_rule = {}
        handlers = [self.on_journal, self.triggers.on_journal] + ([tracker.add] if tracker else [])
        self.stream = JournalStream(db, handlers) if stream else None
        self.last_gc = self.last_persist = time.time()

    # ── loop ──────────────────────────────────────────────────────────────
    def run(self) -> None:
        log.info("sentinel started (tick %ss)", self.s.sentinel_interval)
        if self.stream:
            self.stream.start()
        while not self.stop_event.is_set():
            started = time.time()
            self.tick()
            self.stop_event.wait(max(1.0, self.s.sentinel_interval - (time.time() - started)))

    def tick(self) -> None:
        self.auth.seconds = self.s.ssh_window  # may have been tuned by the agent
        for name, fn in (("metrics", self.check_metrics), ("web", self.check_web), ("auth_files", self.check_auth_files),
                         ("triggers", self.triggers.tick), ("errors", self.tracker.flush if self.tracker else None)):
            if fn is None:
                continue
            try:
                fn()
            except Exception:  # noqa: BLE001 — keep the reflex loop alive no matter what
                log.exception("sentinel check %s failed", name)
        now = time.time()
        if now - self.last_gc > 300:
            for w in (self.auth, self.http_req, self.http_4xx, self.http_auth, self.http_exploit):
                w.gc()
            self.recently_banned = {k: v for k, v in self.recently_banned.items() if v > now}
            self.last_gc = now
        if now - self.last_persist > 600:
            self.db.kv_set("anomaly.baselines", json.dumps(self.anomaly.dump()))
            self.last_persist = now

    def stop(self) -> None:
        self.stop_event.set()
        if self.stream:
            self.stream.stop()

    # ── helpers ───────────────────────────────────────────────────────────
    def _ban(self, ip: str, reason: str, edge: bool = False) -> None:
        now = time.time()
        if self.recently_banned.get(ip, 0) > now:
            return
        ok, _ = self.bans.ban(ip, reason, "sentinel", severity="info", edge=edge)
        self.recently_banned[ip] = now + (300 if ok else 900)
        if ok:
            self.recent_bans.append((now, reason.split(":")[0]))
            self._attack_wave(now)

    def _notable(self, key: str, kind: str, severity: str, details: str, ip: str | None = None, cooldown: int = 1800) -> None:
        now = time.time()
        if self.noted.get(key, 0) > now:
            return
        self.noted[key] = now + cooldown
        self.db.add_event("sentinel", kind, severity, details, ip=ip)
        self.wake()

    def _attack_wave(self, now: float) -> None:
        while self.recent_bans and self.recent_bans[0][0] < now - 600:
            self.recent_bans.popleft()
        if len(self.recent_bans) >= self.s.attack_wave_bans:
            kinds = Counter(k for _, k in self.recent_bans)
            self._notable("attack_wave", "attack_wave", "high",
                          f"{len(self.recent_bans)} IPs banned in 10 min ({dict(kinds.most_common(5))}). Sentinel is containing it; "
                          f"review whether stronger measures are needed. {self.sampler.top_talkers()}")

    # ── journal (real time) ───────────────────────────────────────────────
    def on_journal(self, e: dict) -> None:
        ident = e["ident"]
        if ident in SSH_IDENTS:
            self.handle_ssh(e["msg"], e["ts"])
            return
        for rule in AUTH_RULES:
            if ident in rule["idents"]:
                ip = match_auth_failure(rule, e["msg"])
                if ip:
                    self.auth_failure(rule["name"], ip, e["msg"])
                return

    def handle_ssh(self, msg: str, ts: float | None = None) -> None:
        parsed = parse_ssh_message(msg)
        if not parsed:
            return
        kind, ip, user = parsed
        if kind == "accepted":
            known = ip in self.db.trusted_ips(365 * 86400)
            self.db.trusted_add(ip, user)
            self.auth.reset(f"ssh|{ip}")
            if not known:
                self.db.add_event("sentinel", "ssh_login_new_ip", "medium", f"successful SSH login for '{user}' from new IP {ip}", ip=ip)
                self.wake()
            return
        score = self.auth.add(f"ssh|{ip}", SSH_WEIGHTS.get(kind, 0), ts)
        if score >= self.s.ssh_max_failures:
            self.auth.reset(f"ssh|{ip}")
            self._ban(ip, f"SSH brute force: score {score:.0f} in {self.s.ssh_window}s (last: {kind} user '{user}')")

    def auth_failure(self, service: str, ip: str, line: str) -> None:
        if self.bans.is_protected(ip):
            return
        n = self.auth.add(f"{service}|{ip}")
        if n >= self.s.ssh_max_failures:
            self.auth.reset(f"{service}|{ip}")
            self._ban(ip, f"{service} brute force: {n:.0f} failed logins in {self.s.ssh_window}s")

    def check_auth_files(self) -> None:
        for path, line in self.auth_files.read():
            for rule in AUTH_RULES:
                if any(path.startswith(f.split("*")[0]) for f in rule["files"]):
                    ip = match_auth_failure(rule, line)
                    if ip:
                        self.auth_failure(rule["name"], ip, line)

    # ── metrics, connection floods, anomalies ─────────────────────────────
    def check_metrics(self) -> None:
        snap = self.sampler.sample()
        tcp = self.sampler.tcp
        if tcp:
            for ip, n in tcp.inbound_per_ip.items():
                if n > self.s.conn_per_ip_max and not _private(ip) and not self.bans.proxies.match(ip):
                    self._ban(ip, f"connection flood: {n} established inbound connections (limit {self.s.conn_per_ip_max})")
        for kind, sev, msg in self.anomaly.check(snap):
            if sev == "info":
                self.db.add_event("sentinel", kind, "info", msg)
                continue
            web = ", ".join(f"{ip}×{n:.0f}" for ip, n in self.http_req.top(5))
            self._notable(kind, kind, sev, f"{msg}. {self.sampler.top_talkers()}" + (f" | top HTTP clients/min: {web}" if web else ""), cooldown=1800)

    # ── web logs ──────────────────────────────────────────────────────────
    def check_web(self) -> None:
        n = n4 = n5 = 0
        for _, line in self.web.read():
            p = parse_web_line(line)
            if not p:
                continue
            n += 1
            if 400 <= p[3] < 500:
                n4 += 1
            elif p[3] >= 500:
                n5 += 1
            self.handle_web(*p)
        if n:
            self.sampler.add("http.req", n)
            self.sampler.add("http.4xx", n4)
            self.sampler.add("http.5xx", n5)

    def _web_ban(self, ip: str, reason: str) -> None:
        if _private(ip) and not self.s.web_ban_private:
            # almost always a reverse proxy / load balancer: banning it would take the site down
            self._notable(f"webpriv|{ip}", "web_abuse_private_ip", "medium",
                          f"{reason} — from private address {ip}, NOT banned (likely a reverse proxy; log the real client IP "
                          "or set WEB_BAN_PRIVATE=true)", ip=ip, cooldown=3600)
            return
        self._ban(ip, reason, edge=True)  # traffic may arrive via Cloudflare: block at the edge too when configured

    def handle_web(self, ip: str, method: str, path: str, status: int, ua: str = "") -> None:
        if ip.startswith("127.") or ip == "::1":
            return
        proxy = self.bans.proxies.match(ip)
        if proxy:
            # the log shows the proxy, not the visitor: nothing can be attributed until real-IP logging is fixed
            self._notable("proxy-ip-in-logs", "web_logs_show_proxy_ips", "medium",
                          f"Web access logs record {proxy} addresses (e.g. {ip}) instead of real visitors, so web attacks can't be "
                          "attributed or banned. Configure real-IP logging (nginx: set_real_ip_from <cloudflare ranges>; "
                          "real_ip_header CF-Connecting-IP; Caddy: trusted_proxies + client_ip).", ip=ip, cooldown=86400)
            return
        if ua and SCANNER_UA.search(ua):
            self._web_ban(ip, f"web scanner: user-agent '{ua[:60]}' ({method} {path[:100]})")
            return
        if self.http_req.add(ip) > self.s.http_max_req_per_min:
            self.http_req.reset(ip)
            self._web_ban(ip, f"HTTP flood: >{self.s.http_max_req_per_min} requests/min")
            return
        if status in (401, 403) and (method == "POST" or AUTH_PATH.search(path)):
            if self.http_auth.add(ip) >= self.s.http_auth_fail_max:
                self.http_auth.reset(ip)
                self._web_ban(ip, f"credential stuffing: {self.s.http_auth_fail_max} failed logins in 10 min (e.g. {method} {path[:100]})")
                return
        if 400 <= status < 500 and status != 429:
            if self.http_4xx.add(ip) > self.s.http_max_4xx_per_min:
                self.http_4xx.reset(ip)
                self._web_ban(ip, f"HTTP scanner: >{self.s.http_max_4xx_per_min} 4xx responses/min (last {status} {path[:100]})")
                return
        if is_exploit_probe(path):
            hits = self.http_exploit.add(ip)
            if hits >= self.s.http_exploit_hits:
                self.http_exploit.reset(ip)
                self._web_ban(ip, f"exploit probing: {hits:.0f} malicious requests (e.g. {method} {path[:140]})")
