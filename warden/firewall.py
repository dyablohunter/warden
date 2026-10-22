"""nftables management (own `inet warden` table) and the BanManager shared by sentinel and agent."""
from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import time
from pathlib import Path

from warden import util

log = logging.getLogger("warden.firewall")

TABLE = "warden"

SYSCTL_HARDENING = {
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.tcp_synack_retries": "2",
    "net.ipv4.tcp_max_syn_backlog": "4096",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv6.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians": "1",
}


def build_ruleset(syn_rate: int, conn_limit: int, icmp_rate: int) -> str:
    """Ruleset for our table. Policy accept: we only drop banned sources and per-source floods."""
    lines = [
        f"table inet {TABLE} {{",
        "  set allow4 { type ipv4_addr; flags interval; }",
        "  set allow6 { type ipv6_addr; flags interval; }",
        "  set ban4 { type ipv4_addr; flags interval, timeout; }",
        "  set ban6 { type ipv6_addr; flags interval, timeout; }",
        "  set synflood4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; size 131072; }",
        "  set synflood6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; size 131072; }",
        "  set connlimit4 { type ipv4_addr; flags dynamic; size 131072; }",
        "  set connlimit6 { type ipv6_addr; flags dynamic; size 131072; }",
        "  chain input {",
        "    type filter hook input priority -10; policy accept;",
        '    iif "lo" accept',
        "    ip saddr @allow4 accept",
        "    ip6 saddr @allow6 accept",
        "    ip saddr @ban4 counter drop comment \"warden-ban\"",
        "    ip6 saddr @ban6 counter drop comment \"warden-ban\"",
        "    ct state invalid counter drop comment \"invalid\"",
        "    ct state established,related accept",
    ]
    if syn_rate > 0:
        burst = syn_rate * 2
        lines += [
            f"    tcp flags & (fin|syn|rst|ack) == syn add @synflood4 {{ ip saddr limit rate over {syn_rate}/second burst {burst} packets }} counter drop comment \"syn-flood\"",
            f"    tcp flags & (fin|syn|rst|ack) == syn add @synflood6 {{ ip6 saddr limit rate over {syn_rate}/second burst {burst} packets }} counter drop comment \"syn-flood\"",
        ]
    if conn_limit > 0:
        lines += [
            f"    meta l4proto tcp ct state new add @connlimit4 {{ ip saddr ct count over {conn_limit} }} counter drop comment \"conn-limit\"",
            f"    meta l4proto tcp ct state new add @connlimit6 {{ ip6 saddr ct count over {conn_limit} }} counter drop comment \"conn-limit\"",
        ]
    if icmp_rate > 0:
        lines += [
            f"    icmp type echo-request limit rate over {icmp_rate}/second burst {icmp_rate * 2} packets counter drop comment \"icmp-flood\"",
            f"    icmpv6 type echo-request limit rate over {icmp_rate}/second burst {icmp_rate * 2} packets counter drop comment \"icmp-flood\"",
        ]
    lines += [
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -10; policy accept;",
        "    ip saddr @allow4 accept",
        "    ip6 saddr @allow6 accept",
        "    ip saddr @ban4 counter drop comment \"warden-ban\"",
        "    ip6 saddr @ban6 counter drop comment \"warden-ban\"",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def normalize_target(target: str) -> tuple[str, int]:
    """'1.2.3.4' / '1.2.3.0/24' / '2001:db8::1' -> (canonical string, ip version). Raises ValueError."""
    net = ipaddress.ip_network(target.strip(), strict=False)
    if net.num_addresses == 1:
        return str(net.network_address), net.version
    if (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 32):
        raise ValueError(f"refusing to ban a range as large as {net}")
    return str(net), net.version


class Firewall:
    def __init__(self, settings):
        self.s = settings
        self.available = shutil.which("nft") is not None
        self.ready = False
        self.last_error = ""

    def setup(self) -> bool:
        if not self.available:
            self.last_error = "nft binary not found (apt install nftables)"
            log.error(self.last_error)
            return False
        ruleset = build_ruleset(self.s.nft_syn_rate, self.s.nft_conn_limit, self.s.nft_icmp_rate)
        script = f"table inet {TABLE}\ndelete table inet {TABLE}\n{ruleset}"
        res = util.run(["nft", "-f", "-"], timeout=30, input_text=script)
        if not res.ok:
            # fallback without the optional flood rules (older kernels may lack dynamic-set features)
            log.warning("full ruleset failed (%s); retrying with bans only", res.stderr.strip()[:300])
            script = f"table inet {TABLE}\ndelete table inet {TABLE}\n{build_ruleset(0, 0, 0)}"
            res = util.run(["nft", "-f", "-"], timeout=30, input_text=script)
        if not res.ok:
            self.last_error = res.stderr.strip()[:500]
            log.error("nftables setup failed: %s", self.last_error)
            return False
        self.ready = True
        return True

    def set_allowlist(self, entries: list[str]) -> None:
        if not self.ready:
            return
        util.run(["nft", "flush", "set", "inet", TABLE, "allow4"], timeout=10)
        util.run(["nft", "flush", "set", "inet", TABLE, "allow6"], timeout=10)
        for e in entries:
            try:
                net = ipaddress.ip_network(e, strict=False)
            except ValueError:
                log.warning("ignoring invalid allowlist entry %r", e)
                continue
            s = "allow4" if net.version == 4 else "allow6"
            util.run(["nft", "add", "element", "inet", TABLE, s, "{", str(net), "}"], timeout=10)

    def ban(self, target: str, seconds: int) -> tuple[bool, str]:
        if not self.ready:
            return False, self.last_error or "firewall not initialised"
        canon, ver = normalize_target(target)
        s = "ban4" if ver == 4 else "ban6"
        util.run(["nft", "delete", "element", "inet", TABLE, s, "{", canon, "}"], timeout=10)
        res = util.run(["nft", "add", "element", "inet", TABLE, s, "{", canon, "timeout", f"{max(60, int(seconds))}s", "}"], timeout=10)
        return res.ok, res.stderr.strip()[:300]

    def unban(self, target: str) -> tuple[bool, str]:
        if not self.ready:
            return False, self.last_error or "firewall not initialised"
        canon, ver = normalize_target(target)
        s = "ban4" if ver == 4 else "ban6"
        res = util.run(["nft", "delete", "element", "inet", TABLE, s, "{", canon, "}"], timeout=10)
        return res.ok, res.stderr.strip()[:300]

    def counters(self) -> dict[str, int]:
        """Packets dropped per rule comment, e.g. {'warden-ban': 123, 'syn-flood': 4}."""
        if not self.ready:
            return {}
        res = util.run(["nft", "-j", "list", "table", "inet", TABLE], timeout=15)
        out: dict[str, int] = {}
        try:
            for item in json.loads(res.stdout).get("nftables", []):
                rule = item.get("rule")
                if not rule or not rule.get("comment"):
                    continue
                for e in rule.get("expr", []):
                    if "counter" in e:
                        out[rule["comment"]] = out.get(rule["comment"], 0) + int(e["counter"].get("packets", 0))
        except (json.JSONDecodeError, AttributeError):
            pass
        return out


def apply_sysctl_hardening() -> str:
    path = Path("/etc/sysctl.d/90-warden.conf")
    body = "# Managed by Warden — network hardening\n" + "".join(f"{k} = {v}\n" for k, v in SYSCTL_HARDENING.items())
    try:
        if not path.exists() or path.read_text() != body:
            path.write_text(body)
        res = util.run(["sysctl", "-q", "-p", str(path)], timeout=15)
        return "ok" if res.ok else res.stderr.strip()[:300]
    except OSError as exc:
        return str(exc)


def own_addresses() -> set[str]:
    res = util.run(["ip", "-j", "addr"], timeout=10)
    out: set[str] = set()
    try:
        for iface in json.loads(res.stdout or "[]"):
            for a in iface.get("addr_info", []):
                out.add(a.get("local", ""))
    except json.JSONDecodeError:
        pass
    out.discard("")
    return out


class BanManager:
    """Single entry point for banning: protection checks, escalation, persistence, events."""

    def __init__(self, settings, db, firewall: Firewall, proxies=None, edge=None):
        from warden.proxies import CloudflareEdge, Proxies

        self.s, self.db, self.fw = settings, db, firewall
        self.proxies = proxies if proxies is not None else Proxies(getattr(settings, "trusted_proxies", []), db)
        self.edge = edge if edge is not None else CloudflareEdge(getattr(settings, "cloudflare_api_token", ""),
                                                                   getattr(settings, "cloudflare_account_id", ""),
                                                                   getattr(settings, "cloudflare_zone_id", ""))
        self._own: set[str] = set()
        self._own_ts = 0.0
        self._allow_nets = []
        for e in settings.allowlist:
            try:
                self._allow_nets.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                pass

    def own(self) -> set[str]:
        if time.time() - self._own_ts > 600:
            self._own = own_addresses()
            self._own_ts = time.time()
        return self._own

    def protected_reason(self, target: str) -> str | None:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return "not a valid IP/CIDR"
        addr = net.network_address
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
            return "loopback/link-local/special address"
        proxy = self.proxies.match(str(addr))
        if proxy:
            return f"{proxy} proxy address: banning it would cut off legitimate visitors; ban the real client IP (edge=true)"
        for a in self._allow_nets:
            if a.version == net.version and (net.subnet_of(a) or a.subnet_of(net)):
                return f"in WARDEN_ALLOWLIST ({a})"
        trusted = self.db.trusted_ips(self.s.trusted_login_days * 86400)
        for ip in trusted | self.own():
            try:
                if ipaddress.ip_address(ip) in net:
                    return f"contains {ip} ({'own address' if ip in self._own else 'recent successful SSH login'})"
            except ValueError:
                continue
        return None

    def is_protected(self, ip: str) -> bool:
        return self.protected_reason(ip) is not None

    def ban(self, target: str, reason: str, source: str, minutes: int | None = None, severity: str = "medium", edge: bool = False) -> tuple[bool, str]:
        """Ban in nftables; with edge=True also at the Cloudflare edge (needed for traffic that arrives via Cloudflare)."""
        try:
            canon, _ = normalize_target(target)
        except ValueError as exc:
            return False, str(exc)
        why = self.protected_reason(canon)
        if why:
            self.db.add_event(source, "ban_refused", "low", f"refused to ban {canon}: {why}. Reason given: {reason}", ip=canon)
            return False, f"refused: {canon} is protected ({why})"
        if not self.s.autonomy_at_least("contain"):
            self.db.add_event(source, "ban_suggested", severity, f"would ban {canon} (observe mode): {reason}", ip=canon)
            return False, "observe mode: ban recorded as a suggestion only"
        prev = self.db.ban_get(canon)
        count = prev["count"] if prev else 0
        if minutes is None:
            minutes = min(self.s.ban_max_minutes, self.s.ban_base_minutes * (2 ** min(count, 12)))
        minutes = max(1, min(int(minutes), 525600))
        ok, err = self.fw.ban(canon, minutes * 60)
        if not ok:
            self.db.add_event(source, "ban_failed", "high", f"failed to ban {canon}: {err}. Reason: {reason}", ip=canon)
            return False, f"firewall error: {err}"
        self.db.ban_upsert(canon, reason, source, time.time() + minutes * 60)
        where = ""
        if edge and self.edge.enabled and "/" not in canon:
            if prev and prev.get("edge_rule") and prev["active"]:
                where = " + Cloudflare edge (existing rule)"
            else:
                eok, rule = self.edge.block(canon, f"{reason[:200]} (expires in {minutes}m)")
                if eok:
                    self.db.x("UPDATE bans SET edge_rule=? WHERE ip=?", (rule, canon))
                    where = " + Cloudflare edge"
                else:
                    where = f" (Cloudflare edge ban failed: {rule})"
        # routine sentinel bans are recorded as `info` (no LLM); attack waves are escalated by the sentinel itself
        self.db.add_event(source, "ban", severity, f"banned {canon} for {minutes}m{where} (offence #{count + 1}): {reason}", ip=canon)
        log.warning("BAN %s %dm%s (%s) %s", canon, minutes, where, source, reason)
        return True, f"banned {canon} for {minutes} minutes{where} (offence #{count + 1})"

    def unban(self, target: str, reason: str, source: str) -> tuple[bool, str]:
        try:
            canon, _ = normalize_target(target)
        except ValueError as exc:
            return False, str(exc)
        ok, err = self.fw.unban(canon)
        prev = self.db.ban_get(canon)
        if prev and prev.get("edge_rule"):
            self.edge.unblock(prev["edge_rule"])
            self.db.x("UPDATE bans SET edge_rule=NULL WHERE ip=?", (canon,))
        self.db.ban_deactivate(canon)
        self.db.add_event(source, "unban", "low", f"unbanned {canon}: {reason}", ip=canon)
        return True, f"unbanned {canon}" + ("" if ok else f" (firewall said: {err})")

    def expire_edge(self) -> int:
        """Cloudflare access rules don't expire on their own: remove the ones whose ban has ended."""
        if not self.edge.enabled:
            return 0
        n = 0
        for b in self.db.q("SELECT ip, edge_rule FROM bans WHERE edge_rule IS NOT NULL AND (active=0 OR expires<?)", (time.time(),)):
            ok, _ = self.edge.unblock(b["edge_rule"])
            if ok:
                self.db.x("UPDATE bans SET edge_rule=NULL WHERE ip=?", (b["ip"],))
                n += 1
        return n

    def restore(self) -> int:
        """Re-apply still-active bans after a restart (our table is recreated on start)."""
        n = 0
        for b in self.db.bans_active():
            remaining = int(b["expires"] - time.time())
            if remaining > 60 and self.fw.ban(b["ip"], remaining)[0]:
                n += 1
        return n
