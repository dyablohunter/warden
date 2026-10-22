"""Routines: scheduled data collection, gated so the LLM only runs when something is worth a look.

Each collector has a gate:
  changed  — wakes the LLM when its output differs from the last reviewed run (diff is sent, not the dump)
  nonempty — wakes the LLM when it produces output (use with `{since}` windows: "anything new since last run")
  context  — never wakes the LLM; included only when another collector did
`{since}` in a command is replaced with `@<epoch of last reviewed run>` (journalctl syntax), so windows
never overlap or leave gaps. Suppressions (regexes managed by the agent) drop known-benign lines before gating.
"""
from __future__ import annotations

import difflib
import ipaddress
import json
import re
import ssl
import time
from dataclasses import dataclass
from glob import glob

from warden import safety, util

MIN_INTERVAL, MAX_INTERVAL = 5, 7 * 24 * 60
PROTECTED_BOUNDS = (5, 120)  # interval bounds for protected routines
MAX_ROUTINES = 40
COLLECTOR_LIMIT = 6000
CONTEXT_LIMIT = 2500
GATES = ("changed", "nonempty", "context")
EMPTY = {"", "(empty)", "(none)"}

J = "journalctl -q --no-pager -o short-iso"


def _c(name: str, command: str, gate: str = "changed", timeout: int = 60) -> dict:
    return {"name": name, "command": command, "gate": gate, "timeout": timeout}


DEFAULT_ROUTINES: list[dict] = [
    {
        "name": "security_pulse",
        "interval_minutes": 15,
        "protected": 1,
        "description": "Privilege use, account changes, new listeners, new network-active processes, new outbound ports.",
        "collectors": [
            _c("privilege", f"{J} --since {{since}} -t sudo -t su -t pkexec | grep -E 'COMMAND=|session opened|authentication failure' | tail -n 40", "nonempty"),
            _c("account_changes", f"{J} --since {{since}} -t useradd -t usermod -t userdel -t groupadd -t groupmod -t passwd -t chpasswd -t gpasswd -t chage | tail -n 20", "nonempty"),
            _c("listening", "ss -Htlnup | awk '{print $1, $5, $7}' | sed -E 's/,pid=[0-9]+,fd=[0-9]+//g' | sort -u"),
            _c("exposed_services", "@exposed_services"),
            _c("net_processes", "ss -Htnp state established | grep -oE 'users:..\"[^\"]+\"' | sort -u"),
            _c("outbound_ports", "@outbound_ports"),
            _c("ssh_logins", f"{J} --since {{since}} -t sshd -t sshd-session | grep -E 'Accepted|session opened for user root' | tail -n 20", "context"),
            _c("sessions", "who -u", "context"),
            _c("notable_events", "@events", "context"),
            _c("bans", "@bans_recent", "context"),
        ],
        "instructions": (
            "Something in the gated data changed since the last review. Decide if it is legitimate (operator activity, package "
            "updates, Warden's own actions, known services in host memory) or suspicious: unknown sudo/su use, new accounts, "
            "a new listener or publicly exposed database/cache port, a new process with network connections (shells, nc/socat, "
            "python/perl, binaries from /tmp = reverse shell or miner), new outbound ports (3333/4444/14444 = mining pools). "
            "Contain threats. For recurring benign lines use suppress_signal so they stop waking you."
        ),
    },
    {
        "name": "health_pulse",
        "interval_minutes": 30,
        "description": "New error signatures, failed units; resources as context.",
        "collectors": [
            _c("new_errors", "@new_errors", "nonempty"),
            _c("failed_units", "systemctl --failed --no-legend --plain | awk '{print $1}'"),
            _c("metrics", "@metrics", "context"),
            _c("disk", "df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs", "context"),
            _c("top_cpu", "ps -eo pid,user,pcpu,pmem,etimes,comm --sort=-pcpu | head -n 8", "context"),
            _c("top_mem", "ps -eo pid,user,pmem,rss,comm --sort=-rss | head -n 8", "context"),
            _c("triggers_fired", "@triggers_fired", "context"),
        ],
        "instructions": (
            "New error messages (never seen before on this host) appeared, or the set of failed units changed. Find the cause "
            "and fix what is safe to fix. If an error is harmless and expected, suppress it (suppress_signal on new_errors) "
            "so it never wakes you again; if it needs watching, arm a log trigger."
        ),
    },
    {
        "name": "system_sweep",
        "interval_minutes": 1440,
        "description": "Security updates, reboot-required, certificate expiry, time sync, container states, upgrade errors.",
        "collectors": [
            _c("security_updates", "apt list --upgradable 2>/dev/null | grep -- '-security' | cut -d/ -f1 | sort"),
            _c("reboot_required", "cat /var/run/reboot-required.pkgs 2>/dev/null || echo 'no reboot required'"),
            _c("unattended_upgrades", "systemctl is-enabled unattended-upgrades.service apt-daily-upgrade.timer 2>&1; grep -hE 'ERROR|WARNING' /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -n 5 || true"),
            _c("certs_expiring", "@certs_expiring", "nonempty"),
            _c("time_sync", "timedatectl show -p NTPSynchronized"),
            _c("containers", "docker ps -a --format '{{.Names}} {{.State}}' 2>/dev/null | sort || echo 'docker not present'"),
            _c("zombies", "ps -eo stat,comm | awk '$1 ~ /^Z/ {print $2}' | sort -u", "nonempty"),
            _c("needrestart", "needrestart -b 2>/dev/null | grep -E 'NEEDRESTART-(KSTA|SVC)' | sort || echo 'needrestart not installed'"),
            _c("upgradable_count", "apt list --upgradable 2>/dev/null | grep -c upgradable || true", "context"),
            _c("log_usage", "journalctl --disk-usage; du -sh /var/log /var/lib/docker /var/cache/apt 2>/dev/null || true", "context"),
            _c("big_logs", "find /var/log -xdev -type f -size +500M 2>/dev/null | xargs -r du -m | sort -rn | head -n 10", "nonempty"),
        ],
        "instructions": (
            "Pending security updates -> apply them (apt-get update && apt-get -y upgrade) unless unattended-upgrades is healthy "
            "and will do it today. Certificates expiring within 21 days -> renew (certbot renew) and verify. Unsynced clock -> fix "
            "timesyncd/chrony. Exited containers that should run -> investigate. Log files over 500MB -> make sure they rotate "
            "(logrotate config; journald SystemMaxUse) and compress/truncate safely. Never reboot unless allowed; tell the operator."
        ),
    },
    {
        "name": "integrity_sweep",
        "interval_minutes": 1440,
        "description": "Accounts, sudoers, SSH keys, cron, enabled units, SUID files, critical hashes, persistence vectors.",
        "collectors": [
            _c("uid0", "awk -F: '$3 == 0 {print $1}' /etc/passwd"),
            _c("login_users", "awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1, $3, $6, $7}' /etc/passwd"),
            _c("password_status", "passwd -S -a 2>/dev/null | awk '$2 != \"L\" {print $1, $2}'"),
            _c("sudoers", "grep -rhv -E '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null"),
            _c("authorized_keys", "find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null | xargs -r grep -H -o -E '[^ ]+ [^ ]+$'"),
            _c("cron", "grep -hv -E '^[[:space:]]*(#|$)' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null; ls /etc/cron.hourly /etc/cron.daily 2>/dev/null"),
            _c("enabled_units", "systemctl list-unit-files --state=enabled --no-legend --plain | awk '{print $1}'"),
            _c("suid_sgid", "find / -xdev -perm /6000 -type f 2>/dev/null | sort", timeout=180),
            _c("critical_hashes", "sha256sum /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts /etc/ld.so.preload /etc/pam.d/common-auth /etc/pam.d/sshd /etc/profile /etc/bash.bashrc /root/.bashrc 2>&1"),
            _c("kernel_modules", "lsmod | awk 'NR > 1 {print $1}' | sort"),
            _c("deleted_binaries", "ls -l /proc/[0-9]*/exe 2>/dev/null | grep -F '(deleted)' | sed -E 's/.* -> //; s/ [(]deleted[)]$//' | sort -u || true"),
            _c("tmp_executables", "find /tmp /var/tmp /dev/shm -type f -perm /111 -not -path '*/.git/*' 2>/dev/null | head -n 30"),
            _c("package_changes", "grep -hE ' (install|remove|purge) ' /var/log/dpkg.log 2>/dev/null | tail -n 30"),
        ],
        "instructions": (
            "Change-detection sweep: you see diffs against the last reviewed state. Unknown UID 0 accounts, unexpected sudoers "
            "entries or SSH keys, new cron jobs/units, new SUID binaries, executables in /tmp or /dev/shm, processes running "
            "deleted binaries, ld.so.preload = possible compromise: verify against the audit log (Warden's own changes) and "
            "package changes before acting. Confirmed persistence = critical incident."
        ),
    },
    {
        "name": "weekly_review",
        "interval_minutes": 10080,
        "gated": 0,
        "description": "Weekly hardening audit + self-review (adapt routines/triggers/thresholds) + the operator's weekly report.",
        "collectors": [
            _c("week", "@week_summary"),
            _c("runs", "@runs_recent"),
            _c("routines", "@routines"),
            _c("triggers", "@triggers_status"),
            _c("memory", "@memory"),
            _c("settings", "@settings"),
            _c("sshd", "sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|x11forwarding|maxauthtries|allowusers|allowgroups|logingracetime) '"),
            _c("sysctl", "sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects kernel.kptr_restrict kernel.dmesg_restrict kernel.randomize_va_space fs.protected_symlinks fs.protected_hardlinks kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope 2>&1"),
            _c("firewall", "ufw status verbose 2>/dev/null || echo 'ufw not installed'; nft list tables 2>&1 || true"),
            _c("exposed_services", "@exposed_services"),
            _c("proxy_status", "@proxy_status"),
            _c("apparmor", "aa-status 2>/dev/null | head -n 8 || echo 'apparmor tools not installed'"),
            _c("auto_updates", "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo 'auto-upgrades not configured'"),
            _c("modified_packages", "debsums -sc 2>&1 | head -n 40 || echo 'debsums not installed'", timeout=600),
            _c("world_writable_etc", "find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 20"),
            _c("lynis", "lynis audit system --quick --no-colors --no-log 2>/dev/null | grep -E 'Hardening index|Warning|Suggestion|\\[ WARNING \\]' | head -n 60 || echo 'lynis not installed'", timeout=900),
        ],
        "instructions": (
            "1) Hardening: apply low-risk fixes directly (sysctl, PermitEmptyPasswords no, X11Forwarding no, unattended security "
            "upgrades, world-writable files in /etc, databases/caches bound to public interfaces without need). Changes that could "
            "lock someone out (password auth off, SSH port, AllowUsers, default-deny firewall) only after verifying key-based admin "
            "access; otherwise recommend them. Behind Cloudflare: real-IP logging must be configured (nginx set_real_ip_from + "
            "real_ip_header CF-Connecting-IP), edge bans should be enabled, and direct origin access on 80/443 should be "
            "restricted to Cloudflare ranges once you've confirmed every site is proxied. 2) Self-review: close coverage gaps for the services this host runs (service/port/log "
            "triggers, DB auth logging so brute force is visible), delete stale triggers and suppressions, lengthen routines that "
            "never find anything, tune thresholds that banned legitimate users. Consolidate memory: merge related keys, drop stale "
            "facts, keep it short (it is sent with every run). 3) ALWAYS finish with notify=true, severity at least "
            "'medium': this is the operator's weekly report (week summary, what you changed, hardening status, recommendations)."
        ),
    },
]

ONBOARDING_COLLECTORS = [
    _c("os", "cat /etc/os-release | head -n 4; uname -r; uptime; nproc; free -m | head -n 2"),
    _c("disks", "df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs; lsblk -d -o NAME,SIZE,ROTA,MODEL"),
    _c("services", "systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}'"),
    _c("listening", "ss -Htlnup | awk '{print $1, $5, $7}' | sed -E 's/,pid=[0-9]+,fd=[0-9]+//g' | sort -u"),
    _c("exposed_services", "@exposed_services"),
    _c("firewall", "ufw status verbose 2>/dev/null || echo 'ufw not installed'; nft list tables 2>&1 || true"),
    _c("proxy_status", "@proxy_status"),
    _c("log_rotation", "journalctl --disk-usage; grep -hsE '^[[:space:]]*SystemMaxUse' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf || echo 'journald: no SystemMaxUse cap'; ls /etc/logrotate.d | head -n 30; du -sh /var/log 2>/dev/null"),
    _c("web_logs", "ls -la /var/log/nginx /var/log/apache2 /var/log/caddy 2>/dev/null | head -n 20 || echo none"),
    _c("db_logs", "ls -la /var/log/postgresql /var/log/mysql 2>/dev/null | head -n 20 || echo none"),
    _c("containers", "docker ps --format '{{.Names}} {{.Image}} {{.Ports}}' 2>/dev/null || echo 'docker not present'"),
    _c("users", "awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1, $3, $7}' /etc/passwd; find /root /home -maxdepth 3 -name authorized_keys 2>/dev/null"),
    _c("sshd", "sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication) ' || echo 'sshd not installed'"),
    _c("recurring_errors", "@known_errors"),
    _c("triggers", "@triggers_status"),
    _c("metrics", "@metrics"),
]


# ── validation ─────────────────────────────────────────────────────────────
def _probe_command(cmd: str) -> str:
    return cmd.replace("{since}", "@0")


def validate_routine(r: dict, existing: dict | None) -> tuple[dict | None, str | None]:
    name = str(r.get("name", "")).strip()
    if not re.match(r"^[a-z0-9][a-z0-9_.-]{1,63}$", name):
        return None, "name must be 2-64 chars of [a-z0-9_.-]"
    base = dict(existing or {})
    for k in ("description", "instructions"):
        if k in r:
            base[k] = str(r[k])[:4000]
    try:
        if "interval_minutes" in r:
            base["interval_minutes"] = int(r["interval_minutes"])
    except (TypeError, ValueError):
        return None, "interval_minutes must be an integer"
    for k in ("enabled", "gated"):
        if k in r:
            base[k] = 1 if r[k] else 0
    if "collectors" in r:
        cols = []
        for c in r["collectors"] or []:
            cname = str(c.get("name", "")).strip()
            cmd = str(c.get("command", "")).strip()
            gate = c.get("gate", "changed")
            if not re.match(r"^[a-z0-9_.-]{1,40}$", cname):
                return None, f"collector name {cname!r} invalid"
            if gate not in GATES:
                return None, f"collector {cname}: gate must be one of {GATES}"
            if cmd.startswith("@"):
                if cmd not in INTERNAL:
                    return None, f"unknown internal collector {cmd}; available: {sorted(INTERNAL)}"
            else:
                v = safety.is_read_only(_probe_command(cmd))
                if not v.allowed:
                    return None, f"collector {cname!r} must be read-only: {v.reason}"
            cols.append({"name": cname, "command": cmd, "gate": gate, "timeout": max(5, min(900, int(c.get("timeout", 60))))})
        if len(cols) > 25:
            return None, "at most 25 collectors per routine"
        base["collectors"] = cols
    base["name"] = name
    base.setdefault("collectors", [])
    base.setdefault("enabled", 1)
    base.setdefault("gated", 1)
    base.setdefault("suppress", [])
    if "interval_minutes" not in base:
        return None, "interval_minutes is required"
    lo, hi = PROTECTED_BOUNDS if base.get("protected") else (MIN_INTERVAL, MAX_INTERVAL)
    if not lo <= base["interval_minutes"] <= hi:
        return None, f"interval_minutes must be within [{lo}, {hi}]"
    if base.get("protected") and not base["enabled"]:
        return None, f"{name} is protected and cannot be disabled"
    if not base["collectors"] and not base.get("instructions"):
        return None, "a routine needs collectors or instructions"
    if base["gated"] and base["collectors"] and all(c.get("gate") == "context" for c in base["collectors"]):
        return None, "a gated routine needs at least one 'changed' or 'nonempty' collector (or set gated=false)"
    return base, None


# ── internal collectors ────────────────────────────────────────────────────
def _fmt_rows(rows: list[dict], cols: list[str]) -> str:
    if not rows:
        return "(none)"
    return "\n".join(" | ".join(str(r.get(c, "")) for c in cols) for r in rows)


def _events(ctx, since):
    rows = ctx.db.q("SELECT ts,kind,severity,ip,details FROM events WHERE ts>? AND severity!='info' ORDER BY ts DESC LIMIT 30", (since,))
    for r in rows:
        r["ts"] = util.iso(r["ts"])
        r["details"] = r["details"][:200]
    return _fmt_rows(rows, ["ts", "severity", "kind", "ip", "details"])


def _bans_recent(ctx, since):
    rows = ctx.db.q("SELECT substr(reason,1,instr(reason||':',':')-1) AS kind, COUNT(*) n FROM bans WHERE created>? GROUP BY kind ORDER BY n DESC", (since,))
    active = ctx.db.q("SELECT COUNT(*) n FROM bans WHERE active=1 AND expires>?", (time.time(),))[0]["n"]
    return f"active bans: {active}; new since last run by kind:\n" + _fmt_rows(rows, ["kind", "n"])


def _bans_stats(ctx, since):
    week = time.time() - 7 * 86400
    by_kind = ctx.db.q("SELECT substr(reason,1,instr(reason||':',':')-1) AS kind, COUNT(*) n FROM bans WHERE created>? GROUP BY kind ORDER BY n DESC", (week,))
    repeat = ctx.db.q("SELECT ip,count,reason FROM bans WHERE count>2 ORDER BY count DESC LIMIT 10")
    refused = ctx.db.q("SELECT details FROM events WHERE kind='ban_refused' AND ts>? ORDER BY ts DESC LIMIT 10", (week,))
    return ("bans last 7d by kind:\n" + _fmt_rows(by_kind, ["kind", "n"]) + "\nrepeat offenders:\n" + _fmt_rows(repeat, ["ip", "count", "reason"])
            + "\nrefused (protected IPs):\n" + _fmt_rows(refused, ["details"]))


def _new_errors(ctx, since):
    rows = ctx.db.q("SELECT ident,normalized,count,sample,first_seen FROM log_signatures WHERE first_seen>? ORDER BY count DESC LIMIT 40", (since,))
    return "\n".join(f"[{r['ident']}] x{r['count']} first {util.iso(r['first_seen'])}: {r['sample'][:260]}" for r in rows) or "(none)"


def _known_errors(ctx, since):
    rows = ctx.db.q("SELECT ident,count,sample,last_seen FROM log_signatures ORDER BY count DESC LIMIT 25")
    return "\n".join(f"[{r['ident']}] x{r['count']} last {util.ago(r['last_seen'])}: {r['sample'][:200]}" for r in rows) or "(none)"


def _metrics(ctx, since):
    s = getattr(ctx, "sampler", None)
    if s is None:
        from warden.metrics import Sampler

        s = ctx.sampler = Sampler()
    if not s.snapshot:
        s.sample()
        time.sleep(1)
        s.sample()
    return s.render() + "\n" + s.top_talkers()


def _sampler_tcp(ctx):
    s = getattr(ctx, "sampler", None)
    if s is not None and s.tcp is not None:
        return s.tcp
    from warden.metrics import TcpTable

    return TcpTable.read()


DB_CACHE_PORTS = {3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 11211: "memcached",
                  5984: "couchdb", 9042: "cassandra", 8086: "influxdb", 2379: "etcd", 5672: "rabbitmq", 9092: "kafka"}


def _exposed_services(ctx, since):
    from warden.metrics import PROC, parse_proc_tcp

    out = set()
    for f in ("tcp", "tcp6"):
        try:
            rows = parse_proc_tcp((PROC / "net" / f).read_text())
        except OSError:
            continue
        for lip, lp, _, _, st in rows:
            if st != "0A" or lp not in DB_CACHE_PORTS:
                continue
            try:
                a = ipaddress.ip_address(lip)
            except ValueError:
                continue
            if not a.is_loopback:
                out.add(f"{DB_CACHE_PORTS[lp]} :{lp} listening on {lip} (not loopback — check firewall/bind address)")
    return "\n".join(sorted(out)) or "(none: databases/caches are loopback-only)"


def _outbound_ports(ctx, since):
    common = {22, 25, 53, 80, 123, 443, 465, 587, 853, 993, 995}
    ports = sorted(p for p in _sampler_tcp(ctx).outbound_ports if p not in common)
    return " ".join(str(p) for p in ports) or "(none beyond common ports)"


def _proxy_status(ctx, since):
    """Categorical (stable) view of the Cloudflare/reverse-proxy situation for change-gated review."""
    from warden.sentinel import parse_web_line

    bans = getattr(ctx, "bans", None)
    if bans is None:
        return "(proxy awareness unavailable)"
    web = [(lp, ip) for lp, ip in _sampler_tcp(ctx).inbound if lp in (80, 443, 8080, 8443)]
    via = sum(1 for _, ip in web if bans.proxies.match(ip))
    direct = sum(1 for _, ip in web if not bans.proxies.match(ip) and not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_loopback)
    behind = "unknown (no inbound web connections right now)" if not web else ("yes" if via and not direct else ("partial" if via else "no"))
    log_ips = log_proxy = 0
    for pattern in ctx.settings.web_access_logs:
        for f in glob(pattern):
            try:
                with open(f, "rb") as fh:
                    fh.seek(0, 2)
                    fh.seek(max(0, fh.tell() - 65536))
                    lines = fh.read().decode("utf-8", "replace").splitlines()[1:]
            except OSError:
                continue
            for line in lines[-300:]:
                parsed = parse_web_line(line)
                if parsed:
                    log_ips += 1
                    log_proxy += bool(bans.proxies.match(parsed[0]))
    logs = "no access logs found" if not log_ips else ("PROXY IPs logged — real-IP logging misconfigured" if log_proxy > log_ips / 2 else "real client IPs")
    edge = "configured" if bans.edge.enabled else "NOT configured (host bans can't stop attackers coming through Cloudflare)"
    out = [f"web traffic via trusted proxy (Cloudflare): {behind}", f"access logs record: {logs}", f"edge bans: {edge}"]
    if via and direct:
        out.append("origin reachable directly on web ports: yes (requests can bypass Cloudflare; consider allowing 80/443 only from Cloudflare ranges)")
    return "\n".join(out)


def _certs_expiring(ctx, since):
    soon = []
    paths = glob("/etc/letsencrypt/live/*/cert.pem") + glob("/etc/nginx/**/*.crt", recursive=True) + glob("/etc/apache2/**/*.crt", recursive=True)
    for path in sorted(set(paths)):
        try:
            info = ssl._ssl._test_decode_cert(path)  # stdlib; avoids spawning openssl
            exp = ssl.cert_time_to_seconds(info["notAfter"])
        except Exception:  # noqa: BLE001
            continue
        days = (exp - time.time()) / 86400
        if days < 21:
            soon.append(f"{path}: expires in {days:.0f} days ({info['notAfter']})")
    return "\n".join(soon) or "(none)"


def _routines(ctx, since):
    rows = ctx.db.routines()
    out = []
    for r in rows:
        gates = ",".join(f"{c['name']}:{c.get('gate', 'changed')}" for c in r["collectors"])
        out.append(f"{r['name']} enabled={r['enabled']} every={r['interval_minutes']}m gated={r['gated']} last={util.ago(r['last_run'])} "
                   f"[{r['last_status']}] suppressions={len(r['suppress'])} collectors={gates}")
    runs = ctx.db.q("SELECT name, status, COUNT(*) n FROM runs WHERE kind='routine' AND started>? GROUP BY name, status", (time.time() - 7 * 86400,))
    return "\n".join(out) + "\nLLM runs per routine (7d):\n" + _fmt_rows(runs, ["name", "status", "n"])


def _triggers_status(ctx, since):
    out = []
    for t in ctx.db.triggers():
        out.append(f"{t['name']} [{t['kind']}] enabled={t['enabled']} sev={t['severity']} fired={t['fire_count']} "
                   f"last_fired={util.ago(t['last_fired'])} value={t['last_value']} spec={json.dumps(t['spec'])[:160]}")
    return "\n".join(out) or "(none)"


def _triggers_fired(ctx, since):
    rows = ctx.db.q("SELECT kind,COUNT(*) n,MAX(ts) last FROM events WHERE source='trigger' AND ts>? GROUP BY kind", (since,))
    for r in rows:
        r["last"] = util.iso(r["last"])
    return _fmt_rows(rows, ["kind", "n", "last"])


def _incidents_recent(ctx, since):
    rows = ctx.db.q("SELECT id,status,severity,title,checks,updated,resolution FROM incidents WHERE updated>? OR status!='resolved' ORDER BY id DESC LIMIT 30", (time.time() - 7 * 86400,))
    for r in rows:
        r["updated"] = util.iso(r["updated"])
    return _fmt_rows(rows, ["id", "status", "severity", "title", "checks", "updated", "resolution"])


def _runs_recent(ctx, since):
    rows = ctx.db.q("SELECT kind,name,COUNT(*) n, SUM(tokens_in) tin, SUM(tokens_cached) cached, SUM(tokens_out) tout FROM runs WHERE started>? GROUP BY kind,name ORDER BY tin DESC",
                    (time.time() - 7 * 86400,))
    return "LLM runs in last 7d:\n" + _fmt_rows(rows, ["kind", "name", "n", "tin", "cached", "tout"])


def _memory(ctx, since):
    return _fmt_rows(ctx.db.memory_all(), ["key", "value"])


def _settings(ctx, since):
    s = ctx.settings
    keys = ["autonomy", "ssh_max_failures", "ssh_window", "conn_per_ip_max", "http_max_req_per_min", "http_max_4xx_per_min",
            "http_auth_fail_max", "http_exploit_hits", "attack_wave_bans", "ban_base_minutes", "ban_max_minutes",
            "nft_syn_rate", "nft_conn_limit", "sentinel_interval", "daily_token_budget"]
    return "\n".join(f"{k}={getattr(s, k)}" for k in keys) + f"\nallowlist={s.allowlist}\nweb_access_logs={s.web_access_logs}"


def _actions_recent(ctx, since):
    rows = ctx.db.q("SELECT ts,actor,tool,args,ok FROM actions WHERE ts>? AND tool NOT IN ('read_file','run_command','list_incidents','list_routines','list_triggers','list_blocked','test_trigger','finish') ORDER BY ts DESC LIMIT 40",
                    (time.time() - 7 * 86400,))
    for r in rows:
        r["ts"] = util.iso(r["ts"])
        r["args"] = r["args"][:160]
    return _fmt_rows(rows, ["ts", "actor", "tool", "ok", "args"])


def _week_summary(ctx, since):
    week = time.time() - 7 * 86400
    q = ctx.db.q
    n_events = q("SELECT kind, COUNT(*) n FROM events WHERE ts>? GROUP BY kind ORDER BY n DESC LIMIT 15", (week,))
    inc = q("SELECT id,status,severity,title FROM incidents WHERE created>? OR status!='resolved'", (week,))
    runs = q("SELECT COUNT(*) n, SUM(tokens_in) tin, SUM(tokens_cached) cached, SUM(tokens_out) tout FROM runs WHERE started>?", (week,))[0]
    return (_bans_stats(ctx, since) + f"\nevents by kind:\n{_fmt_rows(n_events, ['kind', 'n'])}\nincidents:\n{_fmt_rows(inc, ['id', 'status', 'severity', 'title'])}\n"
            f"LLM: {runs['n']} runs, tokens in/cached/out {runs['tin']}/{runs['cached']}/{runs['tout']}\nactions:\n{_actions_recent(ctx, since)}")


INTERNAL = {
    "@events": _events, "@bans_recent": _bans_recent, "@bans_stats": _bans_stats, "@new_errors": _new_errors,
    "@known_errors": _known_errors, "@metrics": _metrics, "@exposed_services": _exposed_services, "@outbound_ports": _outbound_ports,
    "@certs_expiring": _certs_expiring, "@proxy_status": _proxy_status, "@routines": _routines, "@triggers_status": _triggers_status, "@triggers_fired": _triggers_fired,
    "@incidents_recent": _incidents_recent, "@runs_recent": _runs_recent, "@memory": _memory, "@settings": _settings,
    "@actions_recent": _actions_recent, "@week_summary": _week_summary,
}


# ── collection & gating ────────────────────────────────────────────────────
@dataclass
class Section:
    name: str
    gate: str
    text: str
    signal: bool
    diff: str | None = None
    suppressed: int = 0


def apply_suppress(text: str, patterns: list[str]) -> tuple[str, int]:
    if not patterns:
        return text, 0
    rx = [re.compile(p) for p in patterns]
    kept, dropped = [], 0
    for line in text.splitlines():
        if any(r.search(line) for r in rx):
            dropped += 1
        else:
            kept.append(line)
    return "\n".join(kept), dropped


def make_diff(old: str, new: str) -> str | None:
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0))[2:]
    lines = [ln for ln in lines if not ln.startswith("@@")]
    diff = "\n".join(lines)
    return diff if diff and len(diff) < len(new) else None


def run_collector(c: dict, ctx, since: float) -> str:
    cmd = c["command"]
    if cmd.startswith("@"):
        fn = INTERNAL.get(cmd)
        try:
            return fn(ctx, since) if fn else f"unknown internal collector {cmd}"
        except Exception as exc:  # noqa: BLE001
            return f"internal collector error: {exc}"
    cmd = cmd.replace("{since}", f"@{int(since)}")
    v = safety.is_read_only(cmd)  # defence in depth: validated on save, re-checked before running
    if not v.allowed:
        return f"SKIPPED: not read-only ({v.reason})"
    res = util.run(cmd, timeout=c.get("timeout", 60))
    text = res.stdout
    if not res.ok and res.stderr.strip():
        text += f"\n[exit {res.code}] {res.stderr.strip()[:300]}"
    if res.timed_out:
        text += "\n[TIMED OUT]"
    return text


def collect(routine: dict, ctx, now: float | None = None) -> list[Section]:
    now = now or time.time()
    prev = routine.get("last_outputs") or {}
    if isinstance(prev, str):
        prev = json.loads(prev or "{}")
    since = routine.get("last_run") or (now - routine["interval_minutes"] * 60)
    expires_ok = lambda s: not s.get("expires") or s["expires"] > now  # noqa: E731
    sections = []
    for c in routine["collectors"]:
        gate = c.get("gate", "changed")
        patterns = [s["pattern"] for s in routine.get("suppress", []) if s.get("collector") in (c["name"], "*") and expires_ok(s)]
        text, dropped = apply_suppress(util.truncate(run_collector(c, ctx, since).strip(), COLLECTOR_LIMIT * 2), patterns)
        text = util.truncate(text.strip() or "(empty)", COLLECTOR_LIMIT)
        sec = Section(c["name"], gate, text, False, suppressed=dropped)
        if gate == "nonempty":
            sec.signal = text not in EMPTY
        elif gate == "changed":
            old = prev.get(c["name"])
            sec.signal = old is None or old != text
            if old is not None and sec.signal:
                sec.diff = make_diff(old, text)
        sections.append(sec)
    return sections


def needs_llm(routine: dict, sections: list[Section]) -> bool:
    return not routine.get("gated", 1) or any(s.signal for s in sections)


def outputs_for_storage(sections: list[Section]) -> dict[str, str]:
    return {s.name: s.text for s in sections if s.gate == "changed"}
