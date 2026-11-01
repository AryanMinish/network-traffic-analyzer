"""Decoder tests: build packets with nta.craft, decode them, check every field."""

import struct
import unittest

from nta import craft
from nta.decoder import decode
from nta.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, RawPacket

A_MAC, B_MAC = "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02"
A_IP, B_IP = "192.168.1.10", "203.0.113.10"


def eth_ip(proto, seg, src=A_IP, dst=B_IP):
    return craft.ethernet(A_MAC, B_MAC, 0x0800, craft.ipv4(src, dst, proto, seg, ttl=61))


def dec(frame, linktype=LINKTYPE_ETHERNET):
    return decode(RawPacket(1_700_000_000.0, linktype, frame, len(frame)), 1)


class TestChecksum(unittest.TestCase):
    def test_rfc1071_example(self):
        # Example from RFC 1071 section 3: 0001 f203 f4f5 f6f7 -> checksum 0x220d
        self.assertEqual(craft.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)

    def test_ipv4_header_checksum_verifies_to_zero(self):
        header = craft.ipv4(A_IP, B_IP, 6, b"")[:20]
        self.assertEqual(craft.checksum(header), 0)


class TestLinkAndNetwork(unittest.TestCase):
    def test_ethernet_ipv4_tcp_syn(self):
        p = dec(eth_ip(6, craft.tcp(A_IP, B_IP, 50000, 443, "S", seq=1000)))
        self.assertEqual((p.src_mac, p.dst_mac), (A_MAC, B_MAC))
        self.assertEqual((p.network, p.src_ip, p.dst_ip, p.ttl), ("IPv4", A_IP, B_IP, 61))
        self.assertEqual((p.transport, p.src_port, p.dst_port), ("TCP", 50000, 443))
        self.assertEqual(p.tcp_flags, "S")
        self.assertTrue(p.is_syn)
        self.assertFalse(p.is_synack)
        self.assertEqual(p.service, "HTTPS")
        self.assertEqual(p.tcp_seq, 1000)

    def test_tcp_flag_combinations(self):
        for flags, expect in (("SA", "SA"), ("FA", "AF"), ("RA", "AR"), ("PA", "AP")):
            p = dec(eth_ip(6, craft.tcp(A_IP, B_IP, 1, 2, flags)))
            self.assertEqual(p.tcp_flags, expect)

    def test_arp_request_and_reply(self):
        req = dec(craft.ethernet(A_MAC, "ff:ff:ff:ff:ff:ff", 0x0806,
                                 craft.arp(1, A_MAC, A_IP, "00:00:00:00:00:00", "192.168.1.1")))
        self.assertEqual(req.protocol, "ARP")
        self.assertEqual(req.info, "Who has 192.168.1.1? Tell 192.168.1.10")
        rep = dec(craft.ethernet(B_MAC, A_MAC, 0x0806, craft.arp(2, B_MAC, "192.168.1.1", A_MAC, A_IP)))
        self.assertEqual(rep.arp_op, 2)
        self.assertEqual(rep.info, f"192.168.1.1 is at {B_MAC}")

    def test_icmp_echo(self):
        p = dec(eth_ip(1, craft.icmp_echo(True, 0x1234, 7)))
        self.assertEqual((p.protocol, p.icmp_type, p.icmp_code), ("ICMP", 8, 0))
        self.assertIn("Echo request", p.info)
        self.assertIn("seq=7", p.info)

    def test_raw_ip_linktype(self):
        p = dec(craft.ipv4(A_IP, B_IP, 17, craft.udp(A_IP, B_IP, 5000, 123, craft.ntp_request())), LINKTYPE_RAW)
        self.assertEqual(p.protocol, "NTP")
        self.assertEqual(p.info, "NTP client request")

    def test_ipv6_udp(self):
        src, dst = "fe80::1", "ff02::fb"
        seg = craft.udp6(src, dst, 5353, 5353, craft.dns_query(0, "_http._tcp.local", "PTR"))
        p = dec(craft.ethernet(A_MAC, "33:33:00:00:00:fb", 0x86DD, craft.ipv6(src, dst, 17, seg)))
        self.assertEqual((p.network, p.src_ip, p.dst_ip), ("IPv6", src, dst))
        self.assertEqual(p.protocol, "mDNS")
        self.assertEqual(p.dns_query, "_http._tcp.local")

    def test_vlan_tag(self):
        inner = craft.ipv4(A_IP, B_IP, 1, craft.icmp_echo(True, 1, 1))
        frame = (craft.mac_bytes(B_MAC) + craft.mac_bytes(A_MAC) + struct.pack("!HHH", 0x8100, 42, 0x0800) + inner)
        p = dec(frame)
        self.assertEqual(p.vlan, 42)
        self.assertEqual(p.protocol, "ICMP")

    def test_truncated_packet_is_flagged_not_crashing(self):
        frame = eth_ip(6, craft.tcp(A_IP, B_IP, 1, 80, "S"))[:30]
        p = dec(frame)
        self.assertTrue(p.malformed)


class TestApplicationLayer(unittest.TestCase):
    def test_dns_query_and_response(self):
        q = dec(eth_ip(17, craft.udp(A_IP, B_IP, 40000, 53, craft.dns_query(0xBEEF, "github.com"))))
        self.assertEqual((q.protocol, q.dns_query, q.dns_qtype, q.dns_response), ("DNS", "github.com", "A", False))
        r = dec(eth_ip(17, craft.udp(B_IP, A_IP, 53, 40000,
                                     craft.dns_response(0xBEEF, "github.com", ["203.0.113.40", "2001:db8::40"]))))
        self.assertTrue(r.dns_response)
        self.assertEqual(r.dns_answers, ["203.0.113.40", "2001:db8::40"])
        self.assertEqual(r.dns_id, 0xBEEF)

    def test_dns_nxdomain(self):
        r = dec(eth_ip(17, craft.udp(B_IP, A_IP, 53, 40000, craft.dns_response(1, "nope.example", [], rcode=3))))
        self.assertEqual(r.dns_rcode, 3)
        self.assertIn("NXDOMAIN", r.info)

    def test_http_request_and_response(self):
        req = dec(eth_ip(6, craft.tcp(A_IP, B_IP, 50000, 80, "PA",
                                      payload=craft.http_request("GET", "neverssl.com", "/index.html"))))
        self.assertEqual((req.protocol, req.http_method, req.http_host, req.http_uri),
                         ("HTTP", "GET", "neverssl.com", "/index.html"))
        res = dec(eth_ip(6, craft.tcp(B_IP, A_IP, 80, 50000, "PA", payload=craft.http_response(404, "Not Found", 10))))
        self.assertEqual(res.http_status, 404)

    def test_http_basic_auth_is_detected_but_not_stored(self):
        p = dec(eth_ip(6, craft.tcp(A_IP, B_IP, 50000, 80, "PA", payload=craft.http_request(
            "GET", "router", "/", {"Authorization": "Basic dXNlcjpzZWNyZXQ="}))))
        self.assertTrue(p.http_basic_auth)
        self.assertNotIn("dXNlcjpzZWNyZXQ=", repr(p))

    def test_tls_sni(self):
        p = dec(eth_ip(6, craft.tcp(A_IP, B_IP, 50000, 443, "PA", payload=craft.tls_client_hello("en.wikipedia.org"))))
        self.assertEqual(p.protocol, "TLS")
        self.assertEqual(p.tls_sni, "en.wikipedia.org")

    def test_dhcp_message_type(self):
        payload = craft.dhcp(1, 0xABCD, A_MAC)
        frame = craft.ethernet(A_MAC, "ff:ff:ff:ff:ff:ff", 0x0800,
                               craft.ipv4("0.0.0.0", "255.255.255.255", 17,
                                          craft.udp("0.0.0.0", "255.255.255.255", 68, 67, payload)))
        p = dec(frame)
        self.assertEqual((p.protocol, p.dhcp_type), ("DHCP", "Discover"))


if __name__ == "__main__":
    unittest.main()
