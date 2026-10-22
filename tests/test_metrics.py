import unittest

from warden.metrics import (AnomalyDetector, Sampler, TcpTable, parse_diskstats, parse_net_dev, parse_proc_tcp, parse_snmp,
                            real_mounts, slope_per_s)

SNMP = """Ip: Forwarding DefaultTTL
Ip: 1 64
Tcp: RtoAlgorithm ActiveOpens PassiveOpens
Tcp: 1 10 250
TcpExt: SyncookiesSent ListenDrops
TcpExt: 7 3
"""
DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0
  eth0: 5000 40 0 0 0 0 0 0 7000 50 0 0 0 0 0 0
"""
TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 0200000A:0016 059BCD2D:C350 01 00000000:00000000 00:00000000 00000000     0        0 2 1
   2: 0200000A:0016 059BCD2D:C351 03 00000000:00000000 00:00000000 00000000     0        0 3 1
   3: 0200000A:D431 22D8B85D:0D05 01 00000000:00000000 00:00000000 00000000     0        0 4 1
"""
TCP6 = """  sl  local_address                         remote_address                        st
   0: 0000000000000000FFFF00000200000A:01BB 0000000000000000FFFF0000059BCD2D:C350 01 0
   1: B80D0120000000000000000001000000:01BB B80D0120000000000000000009000000:0005 01 0
"""


class ParserTests(unittest.TestCase):
    def test_snmp(self):
        c = parse_snmp(SNMP)
        self.assertEqual(c["Tcp.PassiveOpens"], 250)
        self.assertEqual(c["TcpExt.SyncookiesSent"], 7)

    def test_net_dev(self):
        d = parse_net_dev(DEV)
        self.assertEqual(d["eth0"], (5000, 40, 7000))

    def test_proc_tcp(self):
        rows = parse_proc_tcp(TCP) + parse_proc_tcp(TCP6)
        self.assertIn(("0.0.0.0", 22, "0.0.0.0", 0, "0A"), rows)
        self.assertIn(("10.0.0.2", 22, "45.205.155.5", 50000, "01"), rows)
        self.assertIn(("10.0.0.2", 443, "45.205.155.5", 50000, "01"), rows)  # v4-mapped v6
        self.assertIn(("2001:db8::1", 443, "2001:db8::9", 5, "01"), rows)
        t = TcpTable(rows)
        self.assertEqual(t.listening, {22})
        self.assertEqual(t.inbound_per_ip["45.205.155.5"], 1)  # :443 isn't listening in this sample
        self.assertEqual(t.syn_recv, ["45.205.155.5"])
        self.assertEqual(t.outbound_ports, {3333, 50000, 5})

    def test_mounts_diskstats_slope(self):
        m = real_mounts("/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sda1 /var/x ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n/dev/sdb /data xfs ro 0 0\n")
        self.assertEqual(m, [("/dev/sda1", "/", "rw,relatime"), ("/dev/sdb", "/data", "ro")])
        d = parse_diskstats("   8       0 sda 1 2 3 4 5 6 7 8 9 1234 11\n   8       1 sda1 1 2 3 4 5 6 7 8 9 999 11\n 259 0 nvme0n1 1 2 3 4 5 6 7 8 9 50 1\n")
        self.assertEqual(d, {"sda": 1234, "nvme0n1": 50})
        self.assertAlmostEqual(slope_per_s([(0, 0), (10, 20), (20, 40)]), 2.0)

    def test_value_aggregation(self):
        s = Sampler()
        s.snapshot = {"disk_used_pct:/": 40.0, "disk_used_pct:/var": 95.0, "disk_full_eta_h:/": 9999.0, "disk_full_eta_h:/var": 3.0}
        self.assertEqual(s.value("disk_used_pct"), (95.0, "disk_used_pct:/var"))
        self.assertEqual(s.value("disk_full_eta_h"), (3.0, "disk_full_eta_h:/var"))
        self.assertEqual(s.value("port_conns", "5432"), (0.0, "port_conns:5432"))
        self.assertEqual(s.value("load1"), (None, "load1"))


class AnomalyTests(unittest.TestCase):
    def test_baseline_fire_and_end(self):
        a = AnomalyDetector(alpha=0.1, warmup=20, consecutive=3)
        for _ in range(30):
            self.assertEqual(a.check({"tcp_passive_opens_ps": 10.0}), [])
        out = []
        for _ in range(3):
            out += a.check({"tcp_passive_opens_ps": 500.0})
        self.assertEqual(out[0][0], "anomaly:tcp_passive_opens_ps")
        mean = a.base["tcp_passive_opens_ps"].mean
        a.check({"tcp_passive_opens_ps": 500.0})
        self.assertEqual(a.base["tcp_passive_opens_ps"].mean, mean)  # doesn't learn the attack
        end = a.check({"tcp_passive_opens_ps": 10.0})
        self.assertEqual(end[0][0], "anomaly_end:tcp_passive_opens_ps")

    def test_floor_and_warmup(self):
        a = AnomalyDetector(alpha=0.1, warmup=5, consecutive=1)
        for _ in range(10):
            a.check({"http_req_ps": 0.1})
        self.assertEqual(a.check({"http_req_ps": 20.0}), [])  # 200x baseline but under the absolute floor
        b = AnomalyDetector(warmup=100, consecutive=1)
        self.assertEqual(b.check({"http_req_ps": 1e6}), [])  # still warming up

    def test_persist(self):
        a = AnomalyDetector()
        a.check({"udp_in_ps": 5.0})
        b = AnomalyDetector()
        b.load(a.dump())
        self.assertEqual(b.base["udp_in_ps"].n, 1)


if __name__ == "__main__":
    unittest.main()
