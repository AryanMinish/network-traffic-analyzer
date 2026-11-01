"""
Minimal packet builder (the reverse of decoder.py).

Used by the unit tests and by scripts/make_sample_pcap.py to create a
reproducible lab capture. Computes real IPv4, TCP, UDP and ICMP checksums so the
generated packets are also valid when opened in Wireshark.
"""

from __future__ import annotations

import ipaddress
import struct


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def ip4(addr: str) -> bytes:
    return ipaddress.IPv4Address(addr).packed


# --------------------------------------------------------------------------- #
# link + network layers
# --------------------------------------------------------------------------- #
def ethernet(src_mac: str, dst_mac: str, eth_type: int, payload: bytes) -> bytes:
    frame = mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", eth_type) + payload
    return frame + b"\x00" * max(0, 60 - len(frame))  # pad to Ethernet minimum (without FCS)


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000,
                         ttl, proto, 0, ip4(src), ip4(dst))
    csum = checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:] + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    header = struct.pack("!IHBB", 6 << 28, len(payload), next_header, hop_limit)
    return (header + ipaddress.IPv6Address(src).packed
            + ipaddress.IPv6Address(dst).packed + payload)


def arp(op: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, mac_bytes(sender_mac),
                       ip4(sender_ip), mac_bytes(target_mac), ip4(target_ip))


# --------------------------------------------------------------------------- #
# transport layer
# --------------------------------------------------------------------------- #
FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, length)


def tcp(src: str, dst: str, sport: int, dport: int, flags: str = "S", seq: int = 0,
        ack: int = 0, window: int = 64240, payload: bytes = b"") -> bytes:
    bits = sum(FLAG_BITS[f] for f in flags)
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, bits, window, 0, 0)
    csum = checksum(_pseudo(src, dst, 6, len(header) + len(payload)) + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    csum = checksum(_pseudo(src, dst, 17, length) + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


def udp6(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = (ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
              + struct.pack("!I3xB", length, 17))
    csum = checksum(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", csum) + payload


def icmp_echo(request: bool, ident: int, seq: int, payload: bytes = b"abcdefghijklmnopqrstuvwabcdefghi") -> bytes:
    header = struct.pack("!BBHHH", 8 if request else 0, 0, 0, ident, seq)
    csum = checksum(header + payload)
    return header[:2] + struct.pack("!H", csum) + header[4:] + payload


# --------------------------------------------------------------------------- #
# application layer
# --------------------------------------------------------------------------- #
DNS_QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def dns_query(ident: int, name: str, qtype: str = "A") -> bytes:
    return (struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
            + dns_name(name) + struct.pack("!HH", DNS_QTYPES[qtype], 1))


def dns_response(ident: int, name: str, answers: list[str], qtype: str = "A",
                 rcode: int = 0, ttl: int = 300) -> bytes:
    flags = 0x8180 | rcode
    msg = (struct.pack("!HHHHHH", ident, flags, 1, len(answers), 0, 0)
           + dns_name(name) + struct.pack("!HH", DNS_QTYPES[qtype], 1))
    for addr in answers:
        ip = ipaddress.ip_address(addr)
        rtype = 1 if ip.version == 4 else 28
        msg += struct.pack("!HHHIH", 0xC00C, rtype, 1, ttl, len(ip.packed)) + ip.packed
    return msg


def http_request(method: str, host: str, uri: str = "/", extra_headers: dict | None = None) -> bytes:
    lines = [f"{method} {uri} HTTP/1.1", f"Host: {host}",
             "User-Agent: Mozilla/5.0 (X11; Linux x86_64) NTA-Lab/1.0", "Accept: */*",
             "Connection: keep-alive"]
    for k, v in (extra_headers or {}).items():
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def http_response(status: int, reason: str, body_len: int = 512, ctype: str = "text/html") -> bytes:
    head = (f"HTTP/1.1 {status} {reason}\r\nServer: nginx\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {body_len}\r\n\r\n").encode()
    return head + b"x" * body_len


def tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    extensions = sni_ext + struct.pack("!HH", 0x002B, 3) + b"\x02\x03\x04"  # supported_versions
    body = (b"\x03\x03" + bytes(32) + b"\x00"                      # version, random, session id
            + struct.pack("!H", 4) + b"\x13\x01\x13\x02"             # cipher suites
            + b"\x01\x00"                                            # compression
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def dhcp(msg_type: int, xid: int, client_mac: str, yiaddr: str = "0.0.0.0") -> bytes:
    op = 1 if msg_type in (1, 3) else 2
    fixed = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000,
                        ip4("0.0.0.0"), ip4(yiaddr), ip4("0.0.0.0"), ip4("0.0.0.0"),
                        mac_bytes(client_mac) + bytes(10), bytes(64), bytes(128))
    options = b"\x63\x82\x53\x63" + bytes([53, 1, msg_type]) + b"\xff"
    return fixed + options


def ntp_request() -> bytes:
    return bytes([0x23]) + bytes(47)  # LI=0, VN=4, mode=3 (client)


def ntp_response() -> bytes:
    return bytes([0x24, 2]) + bytes(46)  # mode=4 (server), stratum 2
