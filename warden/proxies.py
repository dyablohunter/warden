"""Reverse-proxy / CDN awareness (Cloudflare by default) and optional bans at the Cloudflare edge.

Behind Cloudflare, every visitor reaches the origin from a Cloudflare address. So:
  * Cloudflare addresses must never be banned (that would cut off legitimate visitors) and are exempt
    from the per-source nftables limits (many users share them);
  * banning an attacker's real IP in nftables does nothing for proxied traffic — it has to be blocked at
    the edge (Cloudflare IP Access Rules API), which Warden does when CLOUDFLARE_API_TOKEN is set;
  * if access logs show Cloudflare IPs instead of real clients, real-IP logging is misconfigured.
Works the same when only some sites (or none) are behind Cloudflare: decisions are per address.
"""
from __future__ import annotations

import functools
import ipaddress
import json
import logging
import time
import urllib.error
import urllib.request

log = logging.getLogger("warden.proxies")

# https://www.cloudflare.com/ips/ — refreshed weekly at runtime; this is the fallback
CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CLOUDFLARE_V6 = ["2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"]
CF_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
REFRESH_EVERY = 7 * 86400


def parse_ranges(text: str) -> list[str]:
    out = []
    for line in text.split():
        try:
            out.append(str(ipaddress.ip_network(line.strip(), strict=False)))
        except ValueError:
            continue
    return out


class Proxies:
    """TRUSTED_PROXIES entries: 'cloudflare' and/or CIDRs (your own load balancers)."""

    def __init__(self, entries: list[str], db=None):
        self.db = db
        self.cloudflare = any(e.lower() == "cloudflare" for e in entries)
        self.custom = [e for e in entries if e.lower() != "cloudflare"]
        self.nets: list[tuple[str, object]] = []
        self.load()

    def load(self) -> None:
        cf = CLOUDFLARE_V4 + CLOUDFLARE_V6
        if self.db is not None:
            try:
                cached = json.loads(self.db.kv_get("proxies.cloudflare") or "{}")
                if len(cached.get("ranges", [])) >= 10:
                    cf = cached["ranges"]
            except json.JSONDecodeError:
                pass
        nets = [("cloudflare", ipaddress.ip_network(c)) for c in cf] if self.cloudflare else []
        for c in self.custom:
            try:
                nets.append(("trusted-proxy", ipaddress.ip_network(c, strict=False)))
            except ValueError:
                log.warning("ignoring invalid TRUSTED_PROXIES entry %r", c)
        self.nets = nets
        self.match.cache_clear()

    @functools.lru_cache(maxsize=65536)
    def match(self, ip: str) -> str | None:
        """-> provider name if `ip` belongs to a trusted proxy/CDN, else None."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for name, net in self.nets:
            if a.version == net.version and a in net:
                return name
        return None

    def cidrs(self) -> list[str]:
        return [str(n) for _, n in self.nets]

    def refresh(self, force: bool = False) -> str:
        """Re-download Cloudflare's published ranges at most weekly. Best effort; keeps the last good list."""
        if not self.cloudflare or self.db is None:
            return "skipped"
        try:
            last = json.loads(self.db.kv_get("proxies.cloudflare") or "{}").get("ts", 0)
        except json.JSONDecodeError:
            last = 0
        if not force and time.time() - last < REFRESH_EVERY:
            return "fresh"
        ranges: list[str] = []
        try:
            for url in CF_URLS:
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "warden-agent"}), timeout=15) as r:
                    ranges += parse_ranges(r.read().decode())
        except (urllib.error.URLError, OSError) as exc:
            return f"refresh failed: {exc}"
        if len(ranges) < 10:
            return "refresh returned too few ranges; keeping the current list"
        self.db.kv_set("proxies.cloudflare", json.dumps({"ts": time.time(), "ranges": ranges}))
        self.load()
        return f"refreshed: {len(ranges)} Cloudflare ranges"


class CloudflareEdge:
    """Block single IPs at Cloudflare via IP Access Rules (account- or zone-scoped)."""

    API = "https://api.cloudflare.com/client/v4"

    def __init__(self, token: str = "", account_id: str = "", zone_id: str = ""):
        self.token = token
        self.scope = f"accounts/{account_id}" if account_id else (f"zones/{zone_id}" if zone_id else "")

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.scope)

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(
            f"{self.API}/{self.scope}/firewall/access_rules/rules{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            try:
                return json.loads(exc.read().decode() or "{}") | {"success": False, "http": exc.code}
            except json.JSONDecodeError:
                return {"success": False, "http": exc.code}
        except (urllib.error.URLError, OSError) as exc:
            return {"success": False, "errors": [{"message": str(exc)}]}

    def block(self, ip: str, note: str) -> tuple[bool, str]:
        """-> (ok, rule_id or error)."""
        if not self.enabled:
            return False, "Cloudflare edge bans not configured"
        target = "ip6" if ":" in ip else "ip"
        res = self._call("POST", "", {"mode": "block", "configuration": {"target": target, "value": ip}, "notes": f"warden: {note}"[:500]})
        if res.get("success") and res.get("result", {}).get("id"):
            return True, res["result"]["id"]
        return False, json.dumps(res.get("errors") or res)[:300]

    def unblock(self, rule_id: str) -> tuple[bool, str]:
        if not self.enabled:
            return False, "not configured"
        res = self._call("DELETE", f"/{rule_id}")
        return bool(res.get("success")) or res.get("http") == 404, json.dumps(res.get("errors") or "")[:300]
