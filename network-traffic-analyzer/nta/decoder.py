"""
Protocol decoder: turns raw captured bytes into a structured `Packet`.

Every header is decoded by hand with `struct`, layer by layer, following the
relevant RFCs:

  Link layer       Ethernet II (+ 802.1Q VLAN), Linux SLL, BSD loopback, ARP (RFC 826)
  Network layer    IPv4 (RFC 791), IPv6 (RFC 8200), ICMP (RFC 792), ICMPv6 (RFC 4443)
  Transport layer  TCP (RFC 9293), UDP (RFC 768)
  Application      DNS (RFC 1035), HTTP/1.x (RFC 9112), TLS ClientHello SNI (RFC 8446 / 6066),
                   DHCP (RFC 2131), NTP (RFC 5905) and well-known port identification
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

from .pcap import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_NULL, LINKTYPE_RAW, RawPacket

ETH_IPV4, ETH_ARP, ETH_IPV6, ETH_VLAN = 0x0800, 0x0806, 0x86DD, 0x8100
IP_ICMP, IP_TCP, IP_UDP, IP_ICMPV6 = 1, 6, 17, 58

TCP_FLAG_NAMES = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                  (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")]

# Well-known / registered ports used to label traffic (IANA service names)
SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    137: "NETBIOS", 138: "NETBIOS", 139: "NETBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "SYSLOG", 587: "SMTP", 853: "DoT", 993: "IMAPS", 995: "POP3S",
    1900: "SSDP", 3306: "MYSQL", 3389: "RDP", 5353: "mDNS", 5432: "POSTGRES",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect",
              8: "Echo request", 11: "Time exceeded"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
              5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


@dataclass
class Packet:
    """One decoded packet. Fields that do not apply stay at their defaults."""
    number: int = 0
    timestamp: float = 0.0
    length: int = 0                 # bytes on the wire

    # link layer
    src_mac: str = ""
    dst_mac: str = ""
    vlan: int | None = None

    # network layer
    network: str = ""               # IPv4 / IPv6 / ARP / other
    src_ip: str = ""
    dst_ip: str = ""
    ttl: int | None = None
    ip_proto: int | None = None

    # transport layer
    transport: str = ""             # TCP / UDP / ICMP / ICMPv6
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str = ""             # e.g. "S", "SA", "PA", "FA", "R"
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_window: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    payload_len: int = 0

    # ARP
    arp_op: int | None = None       # 1 = request, 2 = reply
    arp_sender_mac: str = ""
    arp_sender_ip: str = ""
    arp_target_ip: str = ""

    # application layer
    protocol: str = "Other"         # highest decoded protocol (like Wireshark's column)
    service: str = ""               # service implied by the well-known port
    dns_id: int | None = None
    dns_response: bool = False
    dns_query: str = ""
    dns_qtype: str = ""
    dns_answers: list[str] = field(default_factory=list)
    dns_rcode: int | None = None
    http_method: str = ""
    http_host: str = ""
    http_uri: str = ""
    http_status: int | None = None
    http_basic_auth: bool = False
    tls_sni: str = ""
    dhcp_type: str = ""
    info: str = ""                  # one-line human readable summary
    malformed: bool = False

    # convenience helpers ---------------------------------------------------
    @property
    def is_syn(self) -> bool:
        return "S" in self.tcp_flags and "A" not in self.tcp_flags

    @property
    def is_synack(self) -> bool:
        return "S" in self.tcp_flags and "A" in self.tcp_flags

    @property
    def source(self) -> str:
        return self.src_ip or self.arp_sender_ip or self.src_mac

    @property
    def destination(self) -> str:
        return self.dst_ip or self.arp_target_ip or self.dst_mac


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def flags_str(flags: int) -> str:
    # Order flags the way people read them: S, A, F, R, P, U, E, C
    order = "SAFRPUEC"
    present = {name for bit, name in TCP_FLAG_NAMES if flags & bit}
    return "".join(ch for ch in order if ch in present)


def service_for(sport: int | None, dport: int | None) -> str:
    """Pick the service name from whichever port is well-known (lower first)."""
    candidates = [p for p in (dport, sport) if p is not None and p in SERVICES]
    if not candidates:
        return ""
    return SERVICES[min(candidates)]


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #
def decode(raw: RawPacket, number: int = 0) -> Packet:
    pkt = Packet(number=number, timestamp=raw.timestamp, length=raw.wire_len)
    try:
        if raw.linktype == LINKTYPE_ETHERNET:
            _ethernet(pkt, raw.data)
        elif raw.linktype == LINKTYPE_LINUX_SLL:
            _sll(pkt, raw.data)
        elif raw.linktype == LINKTYPE_RAW:
            _ip_any(pkt, raw.data)
        elif raw.linktype == LINKTYPE_NULL:
            family = struct.unpack("<I", raw.data[:4])[0]
            if family == 2:
                _ipv4(pkt, raw.data[4:])
            elif family in (24, 28, 30):
                _ipv6(pkt, raw.data[4:])
        else:
            pkt.info = f"Unsupported link type {raw.linktype}"
    except (struct.error, IndexError, ValueError):
        pkt.malformed = True
        if not pkt.info:
            pkt.info = "Malformed / truncated packet"
    if not pkt.info:
        pkt.info = _default_info(pkt)
    return pkt


# --------------------------------------------------------------------------- #
# link layer
# --------------------------------------------------------------------------- #
def _ethernet(pkt: Packet, data: bytes) -> None:
    pkt.dst_mac, pkt.src_mac = mac_str(data[0:6]), mac_str(data[6:12])
    eth_type = struct.unpack("!H", data[12:14])[0]
    offset = 14
    if eth_type == ETH_VLAN:  # 802.1Q tag
        tci, eth_type = struct.unpack("!HH", data[14:18])
        pkt.vlan = tci & 0x0FFF
        offset = 18
    _ethertype(pkt, eth_type, data[offset:])


def _sll(pkt: Packet, data: bytes) -> None:
    addr_len = struct.unpack("!H", data[4:6])[0]
    pkt.src_mac = mac_str(data[6:6 + min(addr_len, 8)])
    eth_type = struct.unpack("!H", data[14:16])[0]
    _ethertype(pkt, eth_type, data[16:])


def _ethertype(pkt: Packet, eth_type: int, payload: bytes) -> None:
    if eth_type == ETH_IPV4:
        _ipv4(pkt, payload)
    elif eth_type == ETH_IPV6:
        _ipv6(pkt, payload)
    elif eth_type == ETH_ARP:
        _arp(pkt, payload)
    else:
        pkt.network = f"0x{eth_type:04x}"
        pkt.protocol = "Ethernet"
        pkt.info = f"EtherType 0x{eth_type:04x}"


def _arp(pkt: Packet, data: bytes) -> None:
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
    pkt.network = pkt.protocol = "ARP"
    pkt.arp_op = op
    if ptype != ETH_IPV4 or hlen != 6 or plen != 4:
        pkt.info = "ARP (non Ethernet/IPv4)"
        return
    sha, spa = data[8:14], data[14:18]
    tpa = data[24:28]
    pkt.arp_sender_mac = mac_str(sha)
    pkt.arp_sender_ip = str(ipaddress.IPv4Address(spa))
    pkt.arp_target_ip = str(ipaddress.IPv4Address(tpa))
    if op == 1:
        if pkt.arp_sender_ip == pkt.arp_target_ip:
            pkt.info = f"Gratuitous ARP for {pkt.arp_sender_ip}"
        else:
            pkt.info = f"Who has {pkt.arp_target_ip}? Tell {pkt.arp_sender_ip}"
    elif op == 2:
        pkt.info = f"{pkt.arp_sender_ip} is at {pkt.arp_sender_mac}"
    else:
        pkt.info = f"ARP opcode {op}"


# --------------------------------------------------------------------------- #
# network layer
# --------------------------------------------------------------------------- #
def _ip_any(pkt: Packet, data: bytes) -> None:
    version = data[0] >> 4
    if version == 4:
        _ipv4(pkt, data)
    elif version == 6:
        _ipv6(pkt, data)


def _ipv4(pkt: Packet, data: bytes) -> None:
    ver_ihl, _tos, total_len, _ident, frag, ttl, proto = struct.unpack("!BBHHHBB", data[:10])
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20:
        raise ValueError("bad IHL")
    pkt.network = pkt.protocol = "IPv4"
    pkt.src_ip = str(ipaddress.IPv4Address(data[12:16]))
    pkt.dst_ip = str(ipaddress.IPv4Address(data[16:20]))
    pkt.ttl, pkt.ip_proto = ttl, proto
    end = total_len if 0 < total_len <= len(data) else len(data)
    payload = data[ihl:end]
    if frag & 0x1FFF:  # not the first fragment: no transport header here
        pkt.info = f"Fragmented IP protocol (proto={proto}, off={(frag & 0x1FFF) * 8})"
        return
    _transport(pkt, proto, payload)


def _ipv6(pkt: Packet, data: bytes) -> None:
    next_header, hop_limit = data[6], data[7]
    pkt.network = pkt.protocol = "IPv6"
    pkt.src_ip = str(ipaddress.IPv6Address(data[8:24]))
    pkt.dst_ip = str(ipaddress.IPv6Address(data[24:40]))
    pkt.ttl = hop_limit
    offset = 40
    # walk common extension headers: hop-by-hop, routing, destination options
    while next_header in (0, 43, 60) and offset + 2 <= len(data):
        nh, ext_len = data[offset], data[offset + 1]
        offset += (ext_len + 1) * 8
        next_header = nh
    if next_header == 44:  # fragment header
        next_header = data[offset]
        offset += 8
    pkt.ip_proto = next_header
    _transport(pkt, next_header, data[offset:])


# --------------------------------------------------------------------------- #
# transport layer
# --------------------------------------------------------------------------- #
def _transport(pkt: Packet, proto: int, data: bytes) -> None:
    if proto == IP_TCP:
        _tcp(pkt, data)
    elif proto == IP_UDP:
        _udp(pkt, data)
    elif proto == IP_ICMP:
        _icmp(pkt, data, "ICMP")
    elif proto == IP_ICMPV6:
        _icmp(pkt, data, "ICMPv6")
    else:
        pkt.info = f"IP protocol {proto}"


def _icmp(pkt: Packet, data: bytes, name: str) -> None:
    pkt.transport = pkt.protocol = name
    pkt.icmp_type, pkt.icmp_code = data[0], data[1]
    if name == "ICMP":
        label = ICMP_TYPES.get(pkt.icmp_type, f"type {pkt.icmp_type}")
        if pkt.icmp_type in (0, 8) and len(data) >= 8:
            ident, seq = struct.unpack("!HH", data[4:8])
            pkt.info = f"{label} id=0x{ident:04x} seq={seq} ttl={pkt.ttl}"
        else:
            pkt.info = f"{label} (code {pkt.icmp_code})"
    else:
        v6 = {128: "Echo request", 129: "Echo reply", 133: "Router solicitation",
              134: "Router advertisement", 135: "Neighbor solicitation",
              136: "Neighbor advertisement"}
        pkt.info = v6.get(pkt.icmp_type, f"ICMPv6 type {pkt.icmp_type}")
    pkt.payload_len = max(0, len(data) - 8)


def _tcp(pkt: Packet, data: bytes) -> None:
    sport, dport, seq, ack, off_flags, window = struct.unpack("!HHIIHH", data[:16])
    header_len = (off_flags >> 12) * 4
    flags = off_flags & 0x01FF
    pkt.transport = pkt.protocol = "TCP"
    pkt.src_port, pkt.dst_port = sport, dport
    pkt.tcp_seq, pkt.tcp_ack, pkt.tcp_window = seq, ack, window
    pkt.tcp_flags = flags_str(flags & 0xFF)
    payload = data[header_len:]
    pkt.payload_len = len(payload)
    pkt.service = service_for(sport, dport)
    pkt.info = (f"{sport} → {dport} [{_flag_words(pkt.tcp_flags)}] "
                f"Seq={seq} Ack={ack} Win={window} Len={len(payload)}")

    if not payload:
        return
    if payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/1."):
        _http(pkt, payload)
    elif payload[0] == 0x16 and len(payload) > 5 and payload[1] == 0x03:
        _tls(pkt, payload)
    elif pkt.service == "DNS" and len(payload) > 2:  # DNS over TCP has a 2-byte length prefix
        _dns(pkt, payload[2:])
    elif pkt.service == "SSH" and payload.startswith(b"SSH-"):
        pkt.protocol = "SSH"
        pkt.info = payload.split(b"\r\n", 1)[0].decode("ascii", "replace")
    elif pkt.service in ("HTTPS", "HTTPS-ALT") and payload[0] in (0x14, 0x15, 0x16, 0x17):
        pkt.protocol = "TLS"
        pkt.info = "TLS application data" if payload[0] == 0x17 else "TLS record"
    elif pkt.service:
        pkt.protocol = pkt.service


def _flag_words(flags: str) -> str:
    words = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH",
             "U": "URG", "E": "ECE", "C": "CWR"}
    return ", ".join(words[c] for c in flags) or "none"


def _udp(pkt: Packet, data: bytes) -> None:
    sport, dport, length, _csum = struct.unpack("!HHHH", data[:8])
    pkt.transport = pkt.protocol = "UDP"
    pkt.src_port, pkt.dst_port = sport, dport
    payload = data[8:length] if 8 <= length <= len(data) else data[8:]
    pkt.payload_len = len(payload)
    pkt.service = service_for(sport, dport)
    pkt.info = f"{sport} → {dport} Len={len(payload)}"

    if pkt.service in ("DNS", "mDNS") and payload:
        _dns(pkt, payload)
        if pkt.service == "mDNS":
            pkt.protocol = "mDNS"
    elif pkt.service == "DHCP" and payload:
        _dhcp(pkt, payload)
    elif pkt.service == "NTP" and payload:
        pkt.protocol = "NTP"
        mode = payload[0] & 0x07
        pkt.info = {3: "NTP client request", 4: "NTP server response"}.get(mode, f"NTP mode {mode}")
    elif pkt.service == "SSDP":
        pkt.protocol = "SSDP"
        pkt.info = payload.split(b"\r\n", 1)[0].decode("ascii", "replace")
    elif pkt.service:
        pkt.protocol = pkt.service


# --------------------------------------------------------------------------- #
# application layer
# --------------------------------------------------------------------------- #
def _dns_name(msg: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    jumped_to = None
    while True:
        if depth > 20 or offset >= len(msg):
            raise ValueError("bad DNS name")
        length = msg[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if jumped_to is None:
                jumped_to = offset + 2
            offset = pointer
            depth += 1
            continue
        labels.append(msg[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), (jumped_to if jumped_to is not None else offset)


def _dns(pkt: Packet, msg: bytes) -> None:
    ident, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    pkt.protocol = "DNS"
    pkt.dns_id = ident
    pkt.dns_response = bool(flags & 0x8000)
    pkt.dns_rcode = flags & 0x000F
    offset = 12
    if qd:
        name, offset = _dns_name(msg, offset)
        qtype, _qclass = struct.unpack("!HH", msg[offset:offset + 4])
        offset += 4
        pkt.dns_query = name
        pkt.dns_qtype = DNS_TYPES.get(qtype, str(qtype))
        for _ in range(qd - 1):  # skip any extra questions
            _, offset = _dns_name(msg, offset)
            offset += 4
    if pkt.dns_response:
        for _ in range(an):
            _, offset = _dns_name(msg, offset)
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[offset:offset + 10])
            offset += 10
            rdata = msg[offset:offset + rdlen]
            if rtype == 1 and rdlen == 4:
                pkt.dns_answers.append(str(ipaddress.IPv4Address(rdata)))
            elif rtype == 28 and rdlen == 16:
                pkt.dns_answers.append(str(ipaddress.IPv6Address(rdata)))
            elif rtype == 5:
                pkt.dns_answers.append(_dns_name(msg, offset)[0])
            offset += rdlen
        status = "" if pkt.dns_rcode == 0 else (" NXDOMAIN" if pkt.dns_rcode == 3 else f" rcode={pkt.dns_rcode}")
        answers = " ".join(pkt.dns_answers[:3])
        pkt.info = f"Standard query response 0x{ident:04x} {pkt.dns_qtype} {pkt.dns_query} {answers}{status}".strip()
    else:
        pkt.info = f"Standard query 0x{ident:04x} {pkt.dns_qtype} {pkt.dns_query}"


def _http(pkt: Packet, payload: bytes) -> None:
    pkt.protocol = "HTTP"
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    first = lines[0]
    if first.startswith("HTTP/1."):
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            pkt.http_status = int(parts[1])
        pkt.info = first
    else:
        parts = first.split(" ")
        pkt.http_method = parts[0]
        pkt.http_uri = parts[1] if len(parts) > 1 else ""
        pkt.info = first
    for line in lines[1:]:
        key, _, value = line.partition(":")
        k = key.strip().lower()
        if k == "host":
            pkt.http_host = value.strip()
        elif k == "authorization" and value.strip().lower().startswith("basic"):
            pkt.http_basic_auth = True  # we only record THAT it happened, never the secret


def _tls(pkt: Packet, payload: bytes) -> None:
    """Find the Server Name Indication in a TLS ClientHello."""
    pkt.protocol = "TLS"
    pkt.info = "TLS handshake"
    if len(payload) < 43 or payload[5] != 0x01:  # handshake type 1 = ClientHello
        if len(payload) > 5 and payload[5] == 0x02:
            pkt.info = "TLS Server Hello"
        return
    pkt.info = "TLS Client Hello"
    i = 5 + 4 + 2 + 32                     # record hdr, handshake hdr, version, random
    sid_len = payload[i]
    i += 1 + sid_len
    cs_len = struct.unpack("!H", payload[i:i + 2])[0]
    i += 2 + cs_len
    comp_len = payload[i]
    i += 1 + comp_len
    if i + 2 > len(payload):
        return
    ext_total = struct.unpack("!H", payload[i:i + 2])[0]
    i += 2
    end = min(len(payload), i + ext_total)
    while i + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", payload[i:i + 4])
        if ext_type == 0 and ext_len >= 5:  # server_name
            name_len = struct.unpack("!H", payload[i + 7:i + 9])[0]
            pkt.tls_sni = payload[i + 9:i + 9 + name_len].decode("ascii", "replace")
            pkt.info = f"TLS Client Hello (SNI={pkt.tls_sni})"
            return
        i += 4 + ext_len


def _dhcp(pkt: Packet, payload: bytes) -> None:
    pkt.protocol = "DHCP"
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        pkt.info = "BOOTP"
        return
    xid = struct.unpack("!I", payload[4:8])[0]
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        length = payload[i + 1]
        if code == 53 and length >= 1:
            pkt.dhcp_type = DHCP_TYPES.get(payload[i + 2], str(payload[i + 2]))
        i += 2 + length
    pkt.info = f"DHCP {pkt.dhcp_type or 'message'} - Transaction ID 0x{xid:08x}"


def _default_info(pkt: Packet) -> str:
    if pkt.network:
        return f"{pkt.network} {pkt.src_ip} → {pkt.dst_ip}"
    return "Unknown frame"
