"""Tests for pcap I/O, statistics and the detection rules."""

import os
import struct
import tempfile
import unittest

from nta import analyze_file, analyze_raw, craft
from nta.detector import Thresholds, detect, shannon_entropy
from nta.pcap import PcapWriter, RawPacket, read_packets

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "lab_traffic.pcap")
M1, M2, GW = "aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:fe"


def frame(src, dst, proto, seg):
    return craft.ethernet(M1, M2, 0x0800, craft.ipv4(src, dst, proto, seg))


def raws(frames, start=1000.0, step=0.01):
    return [RawPacket(start + i * step, 1, f, len(f)) for i, f in enumerate(frames)]


class TestPcapIO(unittest.TestCase):
    def test_write_then_read_roundtrip(self):
        frames = [frame("10.0.0.1", "10.0.0.2", 6, craft.tcp("10.0.0.1", "10.0.0.2", 1, 80, "S"))] * 3
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            with PcapWriter(path) as w:
                for i, f in enumerate(frames):
                    w.write(100.25 + i, f)
            back = list(read_packets(path))
        self.assertEqual(len(back), 3)
        self.assertAlmostEqual(back[0].timestamp, 100.25, places=5)
        self.assertEqual(back[1].data, frames[1])

    def test_pcapng_reader(self):
        f = frame("10.0.0.1", "10.0.0.2", 1, craft.icmp_echo(True, 1, 1))

        def block(btype, body):
            body += b"\x00" * ((4 - len(body) % 4) % 4)
            n = 12 + len(body)
            return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        idb = block(1, struct.pack("<HHI", 1, 0, 65535))
        ticks = int(1_700_000_123.5 * 1e6)
        epb = block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(f), len(f)) + f)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcapng")
            with open(path, "wb") as fh:
                fh.write(shb + idb + epb)
            pk = list(read_packets(path))
        self.assertEqual(len(pk), 1)
        self.assertAlmostEqual(pk[0].timestamp, 1_700_000_123.5, places=3)
        self.assertEqual(pk[0].data, f)


class TestStats(unittest.TestCase):
    def test_counts_and_conversations(self):
        a, b = "10.0.0.1", "10.0.0.2"
        frames = [frame(a, b, 6, craft.tcp(a, b, 5000, 80, "S")),
                  frame(b, a, 6, craft.tcp(b, a, 80, 5000, "SA")),
                  frame(a, b, 6, craft.tcp(a, b, 5000, 80, "A")),
                  frame(a, b, 17, craft.udp(a, b, 5001, 53, craft.dns_query(1, "example.com")))]
        r = analyze_raw(raws(frames))
        st = r.stats
        self.assertEqual(st.total_packets, 4)
        self.assertEqual(st.protocol_packets["DNS"], 1)
        self.assertEqual(len(st.conversations), 2)  # one TCP flow + one UDP flow
        tcp_flow = next(c for c in st.conversations.values() if c.proto == "TCP")
        self.assertEqual(tcp_flow.packets, 3)
        self.assertEqual(tcp_flow.state, "ESTABLISHED")
        self.assertEqual(st.dst_ports[80], 1)


class TestDetectors(unittest.TestCase):
    def test_port_scan_detected(self):
        a, b = "10.0.0.66", "10.0.0.12"
        frames = [frame(a, b, 6, craft.tcp(a, b, 40000, port, "S")) for port in range(1, 41)]
        alerts = analyze_raw(raws(frames)).alerts
        self.assertEqual([x.rule for x in alerts], ["TCP port scan"])
        self.assertEqual(alerts[0].count, 40)

    def test_few_connections_are_not_a_scan(self):
        a, b = "10.0.0.10", "10.0.0.12"
        frames = [frame(a, b, 6, craft.tcp(a, b, 40000 + i, port, "S")) for i, port in enumerate((22, 80, 443))]
        self.assertEqual(analyze_raw(raws(frames)).alerts, [])

    def test_syn_flood_detected(self):
        dst = "10.0.0.20"
        frames = [frame(f"198.18.0.{i % 250 + 1}", dst, 6,
                        craft.tcp(f"198.18.0.{i % 250 + 1}", dst, 1000 + i, 80, "S")) for i in range(300)]
        alerts = analyze_raw(raws(frames, step=0.005)).alerts
        self.assertIn("SYN flood (DoS)", [x.rule for x in alerts])

    def test_icmp_flood_detected(self):
        a, b = "10.0.0.66", "10.0.0.20"
        frames = [frame(a, b, 1, craft.icmp_echo(True, 1, i)) for i in range(150)]
        alerts = analyze_raw(raws(frames, step=0.01)).alerts
        self.assertEqual(alerts[0].rule, "ICMP flood")

    def test_arp_spoof_detected(self):
        good = craft.ethernet(GW, M1, 0x0806, craft.arp(2, GW, "10.0.0.1", M1, "10.0.0.10"))
        evil = craft.ethernet(M2, M1, 0x0806, craft.arp(2, M2, "10.0.0.1", M1, "10.0.0.10"))
        alerts = analyze_raw(raws([good, evil, evil])).alerts
        self.assertEqual(alerts[0].rule, "ARP spoofing")
        self.assertEqual(alerts[0].evidence["spoofed_mac"], M2)

    def test_dns_tunnel_detected(self):
        a, b = "10.0.0.15", "10.0.0.1"
        names = [f"{'q7x2mzk4vb9wp3ty8rn5' * 2}{i:03d}.data.tunnel.example" for i in range(12)]
        frames = [frame(a, b, 17, craft.udp(a, b, 5000 + i, 53, craft.dns_query(i, n, "TXT")))
                  for i, n in enumerate(names)]
        alerts = analyze_raw(raws(frames, step=0.3)).alerts
        self.assertEqual(alerts[0].rule, "DNS tunnelling suspected")

    def test_thresholds_are_configurable(self):
        a, b = "10.0.0.66", "10.0.0.12"
        frames = [frame(a, b, 6, craft.tcp(a, b, 40000, port, "S")) for port in range(1, 11)]
        packets = analyze_raw(raws(frames)).packets
        self.assertEqual(detect(packets), [])
        self.assertEqual(len(detect(packets, Thresholds(portscan_ports=10))), 1)

    def test_entropy(self):
        self.assertEqual(shannon_entropy("aaaa"), 0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)


@unittest.skipUnless(os.path.exists(SAMPLE), "sample capture not generated")
class TestSampleCapture(unittest.TestCase):
    """End-to-end check on the bundled lab capture: every simulated attack is found."""

    @classmethod
    def setUpClass(cls):
        cls.result = analyze_file(SAMPLE)

    def test_all_six_rules_fire(self):
        rules = {a.rule for a in self.result.alerts}
        self.assertEqual(rules, {"SYN flood (DoS)", "TCP port scan", "ARP spoofing", "ICMP flood",
                                 "DNS tunnelling suspected", "Clear-text credentials"})

    def test_no_malformed_packets(self):
        self.assertEqual(self.result.stats.malformed, 0)

    def test_application_protocols_present(self):
        protos = set(self.result.stats.protocol_packets)
        self.assertTrue({"TCP", "TLS", "DNS", "HTTP", "ARP", "ICMP", "DHCP", "NTP"} <= protos)


if __name__ == "__main__":
    unittest.main()
