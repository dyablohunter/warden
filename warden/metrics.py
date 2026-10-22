"""Cheap host telemetry: everything here reads /proc and /sys directly — no subprocesses on the hot path.

Sampler.sample() runs every sentinel tick (~10s) and produces a flat snapshot of gauges and per-second
rates. Triggers, the anomaly detector and routine collectors all read from that one snapshot.
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
import time
from collections import Counter, deque
from pathlib import Path

from warden import util

PROC = Path("/proc")
REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "bcachefs"}
VIRTUAL_IF = re.compile(r"^(lo|veth|docker|br-|virbr|cni|flannel|cali|vxlan|tun|tap|wg|kube|lxc|dummy)")
WHOLE_DISK = re.compile(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+)$")

# counter name -> rate metric (per second)
COUNTER_RATES = {
    "TcpExt.SyncookiesSent": "syncookies_sent_ps",
    "TcpExt.ListenDrops": "listen_drops_ps",
    "Tcp.PassiveOpens": "tcp_passive_opens_ps",
    "Tcp.RetransSegs": "tcp_retrans_ps",
    "Tcp.InErrs": "tcp_in_errs_ps",
    "Udp.InDatagrams": "udp_in_ps",
    "Udp.RcvbufErrors": "udp_rcvbuf_errors_ps",
    "Icmp.InEchos": "icmp_echo_ps",
    "net.rx_packets": "net_rx_pps",
    "net.rx_bytes": "net_rx_bps",
    "net.tx_bytes": "net_tx_bps",
    "http.req": "http_req_ps",
    "http.4xx": "http_4xx_ps",
    "http.5xx": "http_5xx_ps",
}
# metrics that take an argument (mount path / device / port); without an argument they aggregate
PARAM_METRICS = {"disk_used_pct": "max", "inode_used_pct": "max", "disk_full_eta_h": "min", "disk_busy_pct": "max", "port_conns": None}


# ── pure parsers (unit-tested) ─────────────────────────────────────────────
def parse_snmp(text: str) -> dict[str, int]:
    """/proc/net/snmp and /proc/net/netstat: header/value line pairs -> {'Tcp.PassiveOpens': n}."""
    out: dict[str, int] = {}
    lines = text.splitlines()
    for head, vals in zip(lines[::2], lines[1::2]):
        hp, vp = head.split(), vals.split()
        if not hp or hp[0] != vp[0]:
            continue
        prefix = hp[0].rstrip(":")
        for k, v in zip(hp[1:], vp[1:]):
            try:
                out[f"{prefix}.{k}"] = int(v)
            except ValueError:
                pass
    return out


def parse_net_dev(text: str) -> dict[str, tuple[int, int, int]]:
    """/proc/net/dev -> {iface: (rx_bytes, rx_packets, tx_bytes)}."""
    out = {}
    for line in text.splitlines()[2:]:
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            out[name.strip()] = (int(f[0]), int(f[1]), int(f[8]))
    return out


def _hex_ip(h: str) -> str:
    if len(h) == 8:
        return str(ipaddress.IPv4Address(bytes.fromhex(h)[::-1]))
    raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
    ip = ipaddress.IPv6Address(raw)
    return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)


def parse_proc_tcp(text: str) -> list[tuple[str, int, str, int, str]]:
    """/proc/net/tcp{,6} -> [(local_ip, local_port, remote_ip, remote_port, state_hex)]."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 4:
            continue
        try:
            lh, lp = f[1].split(":")
            rh, rp = f[2].split(":")
            out.append((_hex_ip(lh), int(lp, 16), _hex_ip(rh), int(rp, 16), f[3]))
        except ValueError:
            continue
    return out


class TcpTable:
    """One read of /proc/net/tcp{,6}, digested for every consumer."""

    LISTEN, ESTABLISHED, SYN_RECV = "0A", "01", "03"

    def __init__(self, rows):
        self.listening = {lp for _, lp, _, _, st in rows if st == self.LISTEN}
        self.established = [(lp, rip, rp) for _, lp, rip, rp, st in rows if st == self.ESTABLISHED]
        self.syn_recv = [rip for _, lp, rip, _, st in rows if st == self.SYN_RECV]
        self.inbound = [(lp, rip) for lp, rip, _ in self.established if lp in self.listening]
        self.inbound_per_ip = Counter(rip for _, rip in self.inbound)
        self.per_port = Counter(lp for lp, _ in self.inbound)
        self.outbound_ports = {rp for lp, rip, rp in self.established if lp not in self.listening and not rip.startswith("127.") and rip != "::1"}

    @classmethod
    def read(cls) -> "TcpTable":
        rows = []
        for f in ("tcp", "tcp6"):
            try:
                rows += parse_proc_tcp((PROC / "net" / f).read_text())
            except OSError:
                pass
        return cls(rows)


def real_mounts(text: str) -> list[tuple[str, str, str]]:
    """/proc/mounts -> [(device, mountpoint, options)] for real filesystems, one mountpoint per device."""
    seen, out = set(), []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and f[2] in REAL_FS and f[0] not in seen:
            seen.add(f[0])
            out.append((f[0], f[1].replace("\\040", " "), f[3]))
    return out


def parse_diskstats(text: str) -> dict[str, int]:
    """/proc/diskstats -> {disk: io_ticks_ms} for whole disks."""
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 13 and WHOLE_DISK.match(f[2]):
            out[f[2]] = int(f[12])
    return out


def slope_per_s(points: list[tuple[float, float]]) -> float:
    """Least-squares slope of (t, value) points."""
    n = len(points)
    if n < 2:
        return 0.0
    mt = sum(p[0] for p in points) / n
    mv = sum(p[1] for p in points) / n
    den = sum((p[0] - mt) ** 2 for p in points)
    return 0.0 if den == 0 else sum((p[0] - mt) * (p[1] - mv) for p in points) / den


# ── sampler ────────────────────────────────────────────────────────────────
class Sampler:
    def __init__(self):
        self.lock = threading.Lock()
        self.snapshot: dict[str, float] = {}
        self.tcp: TcpTable | None = None
        self.prev: dict[str, float] = {}
        self.prev_ts = 0.0
        self.extra_counters: Counter = Counter()  # fed by log watchers (http.req, ...)
        self.disk_hist: dict[str, deque] = {}
        self.disk_ticks_prev: dict[str, int] = {}
        self.ro_baseline: set[str] | None = None
        self.failed_units_cache = (0.0, 0.0)
        self.link_speed_mbps: float | None = None

    def add(self, counter: str, n: int = 1) -> None:
        with self.lock:
            self.extra_counters[counter] += n

    def _counters(self) -> dict[str, float]:
        c: dict[str, float] = {}
        for f in ("snmp", "netstat"):
            try:
                c.update(parse_snmp((PROC / "net" / f).read_text()))
            except OSError:
                pass
        try:
            devs = parse_net_dev((PROC / "net" / "dev").read_text())
            phys = {k: v for k, v in devs.items() if not VIRTUAL_IF.match(k)}
            c["net.rx_bytes"] = sum(v[0] for v in phys.values())
            c["net.rx_packets"] = sum(v[1] for v in phys.values())
            c["net.tx_bytes"] = sum(v[2] for v in phys.values())
            if self.link_speed_mbps is None and phys:
                busiest = max(phys, key=lambda k: phys[k][0])
                try:
                    sp = float(Path(f"/sys/class/net/{busiest}/speed").read_text().strip())
                    self.link_speed_mbps = sp if sp > 0 else 0.0
                except (OSError, ValueError):
                    self.link_speed_mbps = 0.0
        except OSError:
            pass
        with self.lock:
            c.update({k: float(v) for k, v in self.extra_counters.items()})
        return c

    def sample(self) -> dict[str, float]:
        now = time.time()
        snap: dict[str, float] = {}
        # load / memory
        load1 = os.getloadavg()[0]
        snap["load1"] = load1
        snap["load_per_cpu"] = load1 / max(1, os.cpu_count() or 1)
        try:
            mem = {}
            for line in (PROC / "meminfo").read_text().splitlines():
                k, _, v = line.partition(":")
                mem[k] = int(v.split()[0])
            snap["mem_avail_pct"] = 100.0 * mem.get("MemAvailable", 0) / max(1, mem.get("MemTotal", 1))
            st = mem.get("SwapTotal", 0)
            snap["swap_used_pct"] = 0.0 if st == 0 else 100.0 * (st - mem.get("SwapFree", 0)) / st
        except OSError:
            pass
        try:
            for line in (PROC / "vmstat").read_text().splitlines():
                if line.startswith("oom_kill "):
                    snap["oom_kills"] = float(line.split()[1])
        except OSError:
            pass
        snap["procs_total"] = float(sum(1 for p in os.listdir(PROC) if p.isdigit()))
        # tcp table
        tcp = TcpTable.read()
        snap["conn_total"] = float(len(tcp.established))
        snap["syn_recv"] = float(len(tcp.syn_recv))
        for port, n in tcp.per_port.items():
            snap[f"port_conns:{port}"] = float(n)
        # conntrack
        try:
            cnt = int(Path("/proc/sys/net/netfilter/nf_conntrack_count").read_text())
            mx = int(Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text())
            snap["conntrack_pct"] = 100.0 * cnt / max(1, mx)
        except (OSError, ValueError):
            pass
        # disks
        self._disks(now, snap)
        # counters -> rates
        cur = self._counters()
        dt = now - self.prev_ts if self.prev_ts else 0
        if dt > 0:
            for cname, metric in COUNTER_RATES.items():
                if cname in cur and cname in self.prev:
                    snap[metric] = max(0.0, (cur[cname] - self.prev[cname]) / dt)
            if "net_rx_bps" in snap:
                snap["net_rx_mbps"] = snap["net_rx_bps"] * 8 / 1e6
                snap["net_tx_mbps"] = snap.get("net_tx_bps", 0) * 8 / 1e6
                snap["net_rx_kpps"] = snap.get("net_rx_pps", 0) / 1000
                if self.link_speed_mbps:
                    snap["net_rx_util_pct"] = 100.0 * snap["net_rx_mbps"] / self.link_speed_mbps
        self.prev, self.prev_ts = cur, now
        # failed units: the only subprocess, cached for 60s
        ts, val = self.failed_units_cache
        if now - ts > 60:
            res = util.run("systemctl --failed --no-legend --plain | grep -c .", timeout=15)
            try:
                val = float((res.stdout.strip() or "0").splitlines()[0])
            except (ValueError, IndexError):
                val = 0.0
            self.failed_units_cache = (now, val)
        snap["failed_units"] = val
        with self.lock:
            self.snapshot, self.tcp = snap, tcp
        return snap

    def _disks(self, now: float, snap: dict) -> None:
        try:
            mounts = real_mounts((PROC / "mounts").read_text())
        except OSError:
            mounts = []
        ro = {mp for _, mp, opts in mounts if "ro" in opts.split(",")}
        if self.ro_baseline is None:
            self.ro_baseline = ro  # mounts that were already read-only at start are expected
        snap["ro_mounts"] = float(len(ro - self.ro_baseline))
        used_all, inode_all, eta_all = [], [], []
        for _, mp, opts in mounts:
            if "ro" in opts.split(","):
                continue  # read-only images (often 100% "full") can't fill up; fs-readonly watches remounts
            try:
                st = os.statvfs(mp)
            except OSError:
                continue
            used = (st.f_blocks - st.f_bfree) * st.f_frsize
            total = used + st.f_bavail * st.f_frsize
            if total <= 0:
                continue
            pct = 100.0 * used / total
            snap[f"disk_used_pct:{mp}"] = pct
            used_all.append(pct)
            if st.f_files:
                ip = 100.0 * (st.f_files - st.f_ffree) / st.f_files
                snap[f"inode_used_pct:{mp}"] = ip
                inode_all.append(ip)
            hist = self.disk_hist.setdefault(mp, deque(maxlen=120))
            if not hist or now - hist[-1][0] >= 60:
                hist.append((now, float(used)))
            recent = [p for p in hist if p[0] >= now - 1800]
            eta = 9999.0
            if len(recent) >= 5 and recent[-1][0] - recent[0][0] >= 600:
                rate = slope_per_s(recent)
                if rate > 0:
                    eta = min(9999.0, st.f_bavail * st.f_frsize / rate / 3600)
            snap[f"disk_full_eta_h:{mp}"] = eta
            eta_all.append(eta)
        if used_all:
            snap["disk_used_pct"] = max(used_all)
        if inode_all:
            snap["inode_used_pct"] = max(inode_all)
        if eta_all:
            snap["disk_full_eta_h"] = min(eta_all)
        try:
            ticks = parse_diskstats((PROC / "diskstats").read_text())
        except OSError:
            ticks = {}
        busy = []
        dt = now - self.prev_ts if self.prev_ts else 0
        for dev, t in ticks.items():
            if dt > 0 and dev in self.disk_ticks_prev:
                pct = min(100.0, 100.0 * (t - self.disk_ticks_prev[dev]) / (dt * 1000))
                snap[f"disk_busy_pct:{dev}"] = pct
                busy.append(pct)
        self.disk_ticks_prev = ticks
        if busy:
            snap["disk_busy_pct"] = max(busy)

    def value(self, metric: str, arg: str | None = None) -> tuple[float | None, str]:
        """Look up a metric (optionally parameterised). Returns (value, label)."""
        with self.lock:
            snap = self.snapshot
        if arg:
            key = f"{metric}:{arg}"
            if key in snap:
                return snap[key], key
            if metric == "port_conns":
                return 0.0, key
            if metric in ("disk_used_pct", "inode_used_pct"):
                try:  # arbitrary path, not necessarily a mountpoint
                    st = os.statvfs(arg)
                    if metric == "disk_used_pct":
                        used = st.f_blocks - st.f_bfree
                        return 100.0 * used / max(1, used + st.f_bavail), key
                    return 100.0 * (st.f_files - st.f_ffree) / max(1, st.f_files), key
                except OSError:
                    return None, key
            return None, key
        if metric in PARAM_METRICS and PARAM_METRICS[metric]:
            parts = {k.split(":", 1)[1]: v for k, v in snap.items() if k.startswith(metric + ":")}
            if parts:
                pick = max if PARAM_METRICS[metric] == "max" else min
                k = pick(parts, key=parts.get)
                return parts[k], f"{metric}:{k}"
        return snap.get(metric), metric

    def top_talkers(self, n: int = 5) -> str:
        with self.lock:
            tcp = self.tcp
        if not tcp:
            return ""
        est = ", ".join(f"{ip}×{c}" for ip, c in tcp.inbound_per_ip.most_common(n))
        syn = ", ".join(f"{ip}×{c}" for ip, c in Counter(tcp.syn_recv).most_common(n))
        ports = ", ".join(f":{p}×{c}" for p, c in tcp.per_port.most_common(n))
        return f"top inbound conns: {est or '-'} | top SYN_RECV: {syn or '-'} | busiest ports: {ports or '-'}"

    def render(self) -> str:
        with self.lock:
            snap = dict(self.snapshot)
        keys = ["load1", "load_per_cpu", "mem_avail_pct", "swap_used_pct", "disk_used_pct", "disk_full_eta_h", "disk_busy_pct",
                "conn_total", "syn_recv", "conntrack_pct", "net_rx_mbps", "net_tx_mbps", "net_rx_kpps", "tcp_passive_opens_ps",
                "syncookies_sent_ps", "listen_drops_ps", "udp_in_ps", "icmp_echo_ps", "http_req_ps", "http_5xx_ps", "failed_units"]
        return " ".join(f"{k}={snap[k]:.1f}" for k in keys if k in snap) or "(no samples yet)"


# ── anomaly detection on learned baselines ─────────────────────────────────
# metric -> (absolute floor, multiple of baseline mean, severity)
WATCHED = {
    "tcp_passive_opens_ps": (50, 5, "high"),
    "net_rx_kpps": (20, 5, "high"),
    "net_rx_mbps": (100, 5, "high"),
    "udp_in_ps": (2000, 6, "high"),
    "icmp_echo_ps": (50, 10, "medium"),
    "http_req_ps": (30, 5, "high"),
    "http_5xx_ps": (2, 8, "medium"),
    "tcp_retrans_ps": (200, 8, "medium"),
}


class Baseline:
    __slots__ = ("mean", "var", "n")

    def __init__(self, mean=0.0, var=0.0, n=0):
        self.mean, self.var, self.n = mean, var, n

    def update(self, x: float, alpha: float) -> None:
        if self.n == 0:
            self.mean = x
        else:
            d = x - self.mean
            self.mean += alpha * d
            self.var = (1 - alpha) * (self.var + alpha * d * d)
        self.n += 1


class AnomalyDetector:
    """EWMA mean/variance per rate metric. Fires when value > max(floor, k*mean, mean+6σ) for 3 ticks.

    Catches distributed floods where no single source crosses per-IP limits. Baselines don't learn
    while a metric is anomalous, and are persisted so restarts don't need a new warm-up.
    """

    def __init__(self, alpha: float = 0.002, warmup: int = 180, consecutive: int = 3):
        self.alpha, self.warmup, self.consecutive = alpha, warmup, consecutive
        self.base: dict[str, Baseline] = {m: Baseline() for m in WATCHED}
        self.streak: dict[str, int] = {m: 0 for m in WATCHED}
        self.active: dict[str, bool] = {m: False for m in WATCHED}

    def check(self, snap: dict[str, float]) -> list[tuple[str, str, str]]:
        """-> [(kind, severity, message)] for newly started or ended anomalies."""
        out = []
        for m, (floor, mult, sev) in WATCHED.items():
            x = snap.get(m)
            if x is None:
                continue
            b = self.base[m]
            limit = max(floor, b.mean * mult, b.mean + 6 * (b.var ** 0.5))
            if b.n >= self.warmup and x > limit:
                self.streak[m] += 1
                if self.streak[m] == self.consecutive and not self.active[m]:
                    self.active[m] = True
                    out.append((f"anomaly:{m}", sev, f"{m}={x:.1f} vs baseline {b.mean:.1f} (limit {limit:.1f})"))
                continue  # don't learn the attack
            if self.active[m]:
                self.active[m] = False
                out.append((f"anomaly_end:{m}", "info", f"{m} back to normal ({x:.1f}, baseline {b.mean:.1f})"))
            self.streak[m] = 0
            b.update(x, self.alpha)
        return out

    def dump(self) -> dict:
        return {m: [b.mean, b.var, b.n] for m, b in self.base.items()}

    def load(self, data: dict) -> None:
        for m, v in (data or {}).items():
            if m in self.base and isinstance(v, list) and len(v) == 3:
                self.base[m] = Baseline(*v)
