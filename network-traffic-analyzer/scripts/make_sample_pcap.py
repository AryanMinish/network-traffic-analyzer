"""
Generate samples/lab_traffic.pcap - a reproducible two-minute capture of a small
home/lab LAN, so the analyzer can be demonstrated without sniffing anyone's
real traffic.

Normal activity : DHCP, ARP, DNS, HTTPS (TLS with SNI), HTTP, NTP, ICMP ping,
                  mDNS over IPv6 and a file download
Simulated attacks (for the detection rules):
                  TCP SYN port scan, ARP spoofing, SYN flood, ICMP flood,
                  DNS tunnelling and an HTTP Basic-auth login in clear text

Public addresses come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and RFC 2544 benchmarking range (198.18.0.0/15),
so no real Internet host is represented.

Usage:  python scripts/make_sample_pcap.py [output.pcap]
"""

from __future__ import annotations

import os
import random
import string
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nta import craft  # noqa: E402
from nta.pcap import PcapWriter  # noqa: E402

random.seed(2024)
IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 20, 10, 30, 0, tzinfo=IST).timestamp()
DURATION = 120.0

BCAST = "ff:ff:ff:ff:ff:ff"
GW_IP, GW_MAC = "192.168.1.1", "00:1a:2b:3c:4d:01"
HOSTS = {   # name: (ip, mac)
    "laptop": ("192.168.1.10", "3c:52:82:aa:10:10"),
    "phone": ("192.168.1.11", "a4:83:e7:11:22:11"),
    "desktop": ("192.168.1.12", "70:85:c2:33:44:12"),
    "webserver": ("192.168.1.20", "b8:27:eb:55:66:20"),
    "newdev": ("192.168.1.15", "f0:18:98:77:88:15"),
    "intruder": ("192.168.1.66", "de:ad:be:ef:00:66"),
}
SITES = {   # domain: (ip, port)
    "www.google.com": ("203.0.113.10", 443),
    "en.wikipedia.org": ("203.0.113.25", 443),
    "github.com": ("203.0.113.40", 443),
    "www.youtube.com": ("203.0.113.55", 443),
    "karnavatiuniversity.edu.in": ("198.51.100.30", 443),
    "fonts.gstatic.com": ("203.0.113.70", 443),
    "stackoverflow.com": ("198.51.100.45", 443),
    "docs.python.org": ("198.51.100.60", 443),
    "neverssl.com": ("198.51.100.75", 80),
    "httpforever.com": ("198.51.100.90", 80),
    "mirror.lab.example": ("192.0.2.80", 443),
}
NTP_SERVER = "192.0.2.123"

frames: list[tuple[float, bytes]] = []
ip_id = random.randint(1000, 60000)


def emit(t: float, frame: bytes) -> None:
    if 0 <= t <= DURATION:
        frames.append((T0 + t, frame))


def next_id() -> int:
    global ip_id
    ip_id = (ip_id + 1) & 0xFFFF
    return ip_id


def mac_of(ip: str) -> str:
    for hip, hmac in HOSTS.values():
        if hip == ip:
            return hmac
    return GW_MAC if ip != GW_IP else GW_MAC   # off-LAN traffic goes via the router


def ip_frame(src: str, dst: str, proto: int, seg: bytes, ttl: int = 64, src_mac: str | None = None,
             dst_mac: str | None = None) -> bytes:
    return craft.ethernet(src_mac or mac_of(src), dst_mac or mac_of(dst), 0x0800,
                          craft.ipv4(src, dst, proto, seg, ttl=ttl, ident=next_id()))


def tcp_pkt(t, src, dst, sport, dport, flags, seq, ack, payload=b"", ttl=64, window=64240, **kw):
    emit(t, ip_frame(src, dst, 6, craft.tcp(src, dst, sport, dport, flags, seq, ack, window, payload),
                     ttl=ttl, **kw))


def udp_pkt(t, src, dst, sport, dport, payload, ttl=64, **kw):
    emit(t, ip_frame(src, dst, 17, craft.udp(src, dst, sport, dport, payload), ttl=ttl, **kw))


# --------------------------------------------------------------------------- #
# building blocks
# --------------------------------------------------------------------------- #
def dns_lookup(t, client, name, answer, qtype="A") -> float:
    qid = random.randint(0, 0xFFFF)
    sport = random.randint(49152, 65535)
    udp_pkt(t, client, GW_IP, sport, 53, craft.dns_query(qid, name, qtype))
    rtt = random.uniform(0.008, 0.035)
    udp_pkt(t + rtt, GW_IP, client, 53, sport, craft.dns_response(qid, name, [answer] if answer else [], qtype))
    return t + rtt + 0.002


def tcp_session(t, client, server, dport, request: bytes, response_bytes: int,
                server_ttl=54, mss=1448, close=True, status=(200, "OK")) -> float:
    """Three-way handshake, request, segmented response with ACKs, FIN close."""
    cport = random.randint(49152, 65535)
    cseq, sseq = random.randint(0, 2**31), random.randint(0, 2**31)
    rtt = random.uniform(0.012, 0.06) if not server.startswith("192.168.") else random.uniform(0.0005, 0.003)
    tcp_pkt(t, client, server, cport, dport, "S", cseq, 0)
    tcp_pkt(t + rtt, server, client, dport, cport, "SA", sseq, cseq + 1, ttl=server_ttl, window=65160)
    t += rtt + 0.0004
    cseq += 1
    sseq += 1
    tcp_pkt(t, client, server, cport, dport, "A", cseq, sseq)
    t += 0.0003
    tcp_pkt(t, client, server, cport, dport, "PA", cseq, sseq, request)
    cseq += len(request)
    t += rtt
    tcp_pkt(t, server, client, dport, cport, "A", sseq, cseq, ttl=server_ttl, window=65160)
    if dport == 443:   # ServerHello + certificate, then application data records
        hello = b"\x16\x03\x03\x00\x7a\x02" + bytes(min(mss, 1300))
        tcp_pkt(t + 0.001, server, client, dport, cport, "PA", sseq, cseq, hello, ttl=server_ttl)
        sseq += len(hello)
        t += 0.002
        fin_req = b"\x14\x03\x03\x00\x01\x01\x17\x03\x03\x00\x45" + bytes(69)
        tcp_pkt(t + rtt / 2, client, server, cport, dport, "PA", cseq, sseq, fin_req)
        cseq += len(fin_req)
        t += rtt
    sent, seg_i = 0, 0
    while sent < response_bytes:
        size = min(mss, response_bytes - sent)
        if dport == 443:
            payload = b"\x17\x03\x03" + size.to_bytes(2, "big")[-2:] + bytes(max(0, size - 5))
        elif sent == 0:
            payload = craft.http_response(status[0], status[1], max(0, size - 120))[:size]
        else:
            payload = b"<p>" + bytes(size - 3)
        flags = "PA" if sent + size >= response_bytes else "A"
        tcp_pkt(t, server, client, dport, cport, flags, sseq, cseq, payload, ttl=server_ttl)
        sseq += len(payload)
        sent += size
        seg_i += 1
        t += random.uniform(0.0002, 0.0012)
        if seg_i % 2 == 0 or sent >= response_bytes:
            tcp_pkt(t, client, server, cport, dport, "A", cseq, sseq, window=62000 + 512 * (seg_i % 7))
            t += 0.0002
    if close:
        t += random.uniform(0.05, 0.4)
        tcp_pkt(t, client, server, cport, dport, "FA", cseq, sseq)
        tcp_pkt(t + rtt, server, client, dport, cport, "FA", sseq, cseq + 1, ttl=server_ttl)
        tcp_pkt(t + rtt + 0.0003, client, server, cport, dport, "A", cseq + 1, sseq + 1)
        t += rtt + 0.001
    return t


def visit(t, host, domain, path="/", size=None) -> float:
    client = HOSTS[host][0]
    ip, port = SITES[domain]
    t = dns_lookup(t, client, domain, ip)
    size = size or random.randint(18_000, 140_000)
    if port == 443:
        req = craft.tls_client_hello(domain)
    else:
        req = craft.http_request("GET", domain, path)
    status = (404, "Not Found") if path == "/missing-page" else (200, "OK")
    return tcp_session(t, client, ip, port, req, size, status=status)


# --------------------------------------------------------------------------- #
# normal traffic
# --------------------------------------------------------------------------- #
def dhcp_join(t):
    mac = HOSTS["newdev"][1]
    xid = 0x3903F326
    for i, (mtype, src, dst, smac, dmac) in enumerate([
        (1, "0.0.0.0", "255.255.255.255", mac, BCAST),
        (2, GW_IP, "255.255.255.255", GW_MAC, BCAST),
        (3, "0.0.0.0", "255.255.255.255", mac, BCAST),
        (5, GW_IP, "255.255.255.255", GW_MAC, BCAST),
    ]):
        sport, dport = (68, 67) if mtype in (1, 3) else (67, 68)
        yi = "0.0.0.0" if mtype in (1, 3) else HOSTS["newdev"][0]
        payload = craft.dhcp(mtype, xid, mac, yi)
        emit(t + i * 0.012, craft.ethernet(smac, dmac, 0x0800,
                                           craft.ipv4(src, dst, 17, craft.udp(src, dst, sport, dport, payload),
                                                      ttl=64 if mtype in (1, 3) else 255)))
    # gratuitous ARP announcing the new address
    ip = HOSTS["newdev"][0]
    emit(t + 0.06, craft.ethernet(mac, BCAST, 0x0806, craft.arp(1, mac, ip, "00:00:00:00:00:00", ip)))


def arp_exchange(t, who: str, target_ip: str):
    ip, mac = HOSTS[who]
    tmac = GW_MAC if target_ip == GW_IP else next(m for i, m in HOSTS.values() if i == target_ip)
    emit(t, craft.ethernet(mac, BCAST, 0x0806, craft.arp(1, mac, ip, "00:00:00:00:00:00", target_ip)))
    emit(t + 0.0007, craft.ethernet(tmac, mac, 0x0806, craft.arp(2, tmac, target_ip, mac, ip)))


def ping(t, host, dst, count=4):
    src = HOSTS[host][0]
    ident = random.randint(1, 0xFFFF)
    for seq in range(1, count + 1):
        emit(t, ip_frame(src, dst, 1, craft.icmp_echo(True, ident, seq)))
        emit(t + 0.021, ip_frame(dst, src, 1, craft.icmp_echo(False, ident, seq), ttl=55))
        t += 1.0


def ntp_sync(t, host):
    src = HOSTS[host][0]
    udp_pkt(t, src, NTP_SERVER, 123, 123, craft.ntp_request())
    udp_pkt(t + 0.03, NTP_SERVER, src, 123, 123, craft.ntp_response(), ttl=52)


def mdns_v6(t):
    src = "fe80::a683:e7ff:fe11:2211"
    dst = "ff02::fb"
    payload = craft.dns_query(0, "_googlecast._tcp.local", "PTR")
    seg = craft.udp6(src, dst, 5353, 5353, payload)
    emit(t, craft.ethernet(HOSTS["phone"][1], "33:33:00:00:00:fb", 0x86DD, craft.ipv6(src, dst, 17, seg, 255)))


def normal_traffic():
    dhcp_join(1.0)
    # periodic ARP refreshes
    for t in range(0, 120, 15):
        arp_exchange(t + 0.3, random.choice(["laptop", "phone", "desktop"]), GW_IP)
    arp_exchange(5.2, "laptop", HOSTS["desktop"][0])
    # NTP every 32 s
    for t in (2.5, 34.5, 66.5, 98.5):
        ntp_sync(t, "desktop")
    for t in (8, 38, 68, 98):
        mdns_v6(t + 0.4)
    ping(12.0, "laptop", "203.0.113.10", 4)

    # web browsing sessions
    browsing = [
        (3.0, "laptop", "www.google.com"), (6.4, "laptop", "fonts.gstatic.com"),
        (9.1, "phone", "www.youtube.com"), (14.2, "laptop", "github.com"),
        (17.5, "desktop", "docs.python.org"), (20.3, "newdev", "www.google.com"),
        (24.0, "laptop", "karnavatiuniversity.edu.in"), (27.6, "phone", "en.wikipedia.org"),
        (31.0, "desktop", "stackoverflow.com"), (35.2, "laptop", "neverssl.com"),
        (48.5, "phone", "www.youtube.com"), (52.0, "laptop", "en.wikipedia.org"),
        (56.7, "desktop", "github.com"), (64.5, "newdev", "fonts.gstatic.com"),
        (69.0, "laptop", "httpforever.com"), (82.3, "phone", "www.google.com"),
        (85.0, "desktop", "docs.python.org"), (95.4, "laptop", "stackoverflow.com"),
        (104.0, "phone", "karnavatiuniversity.edu.in"), (111.0, "laptop", "github.com"),
        (115.5, "desktop", "www.google.com"),
    ]
    for t, host, domain in browsing:
        visit(t, host, domain)
    # a few HTTP requests with different status codes
    t = visit(70.5, "laptop", "httpforever.com", "/missing-page", size=900)
    # a larger file download from a mirror (~1.2 MB)
    visit(42.0, "desktop", "mirror.lab.example", size=1_200_000)
    # laptop opens the local web server normally
    tcp_session(22.0, HOSTS["laptop"][0], HOSTS["webserver"][0], 80,
                craft.http_request("GET", "192.168.1.20", "/index.html"), 6_000)
    # router admin page opened over plain HTTP with Basic authentication (clear text!)
    tcp_session(58.0, HOSTS["laptop"][0], GW_IP, 80,
                craft.http_request("GET", "192.168.1.1", "/admin",
                                   {"Authorization": "Basic YWRtaW46bGFiLXBhc3M="}), 3_200)


# --------------------------------------------------------------------------- #
# simulated attacks
# --------------------------------------------------------------------------- #
def port_scan(t):
    """SYN ('half-open') scan of ports 1-200 on the desktop, like `nmap -sS -p1-200`."""
    src, dst = HOSTS["intruder"][0], HOSTS["desktop"][0]
    open_ports = {22, 80, 135, 139}
    ports = list(range(1, 201))
    random.shuffle(ports)
    sport = 51234
    for port in ports:
        seq = random.randint(0, 2**31)
        tcp_pkt(t, src, dst, sport, port, "S", seq, 0, window=1024, ttl=48)
        if port in open_ports:
            sseq = random.randint(0, 2**31)
            tcp_pkt(t + 0.0006, dst, src, port, sport, "SA", sseq, seq + 1, window=64240)
            tcp_pkt(t + 0.0009, src, dst, sport, port, "R", seq + 1, 0, window=0, ttl=48)
        else:
            tcp_pkt(t + 0.0005, dst, src, port, sport, "RA", 0, seq + 1, window=0)
        t += random.uniform(0.012, 0.025)


def arp_spoof(t):
    """Intruder repeatedly tells the laptop and desktop that it is the router."""
    imac = HOSTS["intruder"][1]
    for i in range(12):
        victim = "laptop" if i % 2 == 0 else "desktop"
        vip, vmac = HOSTS[victim]
        emit(t + i * 0.9, craft.ethernet(imac, vmac, 0x0806, craft.arp(2, imac, GW_IP, vmac, vip)))


def syn_flood(t):
    """Spoofed-source SYN flood against the local web server on port 80."""
    dst = HOSTS["webserver"][0]
    for i in range(450):
        src = f"198.18.{random.randint(0, 255)}.{random.randint(1, 254)}"
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 2**31)
        tt = t + i * 0.0055
        tcp_pkt(tt, src, dst, sport, 80, "S", seq, 0, window=512, ttl=random.randint(40, 60),
                src_mac=GW_MAC, dst_mac=HOSTS["webserver"][1])
        if i % 3 == 0:   # server answers until its backlog fills up
            tcp_pkt(tt + 0.0004, dst, src, 80, sport, "SA", random.randint(0, 2**31), seq + 1,
                    src_mac=HOSTS["webserver"][1], dst_mac=GW_MAC)


def icmp_flood(t):
    src, dst = HOSTS["intruder"][0], HOSTS["webserver"][0]
    for seq in range(1, 181):
        emit(t, ip_frame(src, dst, 1, craft.icmp_echo(True, 0x4242, seq, bytes(1000)), ttl=64))
        emit(t + 0.0004, ip_frame(dst, src, 1, craft.icmp_echo(False, 0x4242, seq, bytes(1000))))
        t += 0.009


def dns_tunnel(t):
    """A compromised device leaks data hidden in DNS query names."""
    client = HOSTS["newdev"][0]
    alphabet = string.ascii_lowercase + "234567"
    for i in range(28):
        chunk = "".join(random.choice(alphabet) for _ in range(random.randint(38, 52)))
        name = f"{chunk}.{i:02d}.exfil-lab.example"
        qid = random.randint(0, 0xFFFF)
        sport = random.randint(49152, 65535)
        udp_pkt(t, client, GW_IP, sport, 53, craft.dns_query(qid, name, "TXT"))
        udp_pkt(t + 0.03, GW_IP, client, 53, sport, craft.dns_response(qid, name, [], "TXT", rcode=3))
        t += random.uniform(0.2, 0.45)


def main(out_path: str) -> None:
    normal_traffic()
    port_scan(40.0)
    arp_spoof(60.0)
    syn_flood(75.0)
    icmp_flood(90.0)
    dns_tunnel(100.0)
    frames.sort(key=lambda f: f[0])
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with PcapWriter(out_path) as w:
        for ts, frame in frames:
            w.write(ts, frame)
    print(f"Wrote {len(frames)} packets to {out_path}")


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(__file__), "..", "samples", "lab_traffic.pcap")
    main(sys.argv[1] if len(sys.argv) > 1 else default)
