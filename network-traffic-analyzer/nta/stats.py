"""
Traffic statistics: turns a list of decoded packets into the summaries an
analyst actually looks at - protocol mix, top talkers, ports, conversations,
traffic over time, packet sizes, DNS / HTTP / TLS activity and the ARP table.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .decoder import Packet

SIZE_BUCKETS = [(0, 64), (65, 128), (129, 256), (257, 512), (513, 1024), (1025, 1518), (1519, 10**9)]


@dataclass
class Conversation:
    """A bidirectional flow identified by its 5-tuple."""
    proto: str
    a: str          # "ip:port" of the side that sent the first packet
    b: str
    packets: int = 0
    bytes: int = 0
    a_to_b_bytes: int = 0
    b_to_a_bytes: int = 0
    start: float = 0.0
    end: float = 0.0
    service: str = ""
    syn: bool = False
    synack: bool = False
    fin: bool = False
    rst: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)

    @property
    def state(self) -> str:
        if self.proto != "TCP":
            return "-"
        if self.rst and not self.synack:
            return "REJECTED"
        if self.syn and not self.synack:
            return "NO REPLY"
        if self.fin:
            return "CLOSED"
        if self.rst:
            return "RESET"
        return "ESTABLISHED" if self.synack else "MID-STREAM"


@dataclass
class TrafficStats:
    packets: list[Packet]
    start: float = 0.0
    end: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_packets: Counter = field(default_factory=Counter)
    protocol_bytes: Counter = field(default_factory=Counter)
    network_layer: Counter = field(default_factory=Counter)
    transport_layer: Counter = field(default_factory=Counter)
    host_sent: Counter = field(default_factory=Counter)
    host_recv: Counter = field(default_factory=Counter)
    host_packets: Counter = field(default_factory=Counter)
    dst_ports: Counter = field(default_factory=Counter)
    services: Counter = field(default_factory=Counter)
    tcp_flags: Counter = field(default_factory=Counter)
    size_hist: Counter = field(default_factory=Counter)
    conversations: dict = field(default_factory=dict)
    dns_queries: Counter = field(default_factory=Counter)
    dns_answers: dict = field(default_factory=lambda: defaultdict(set))
    dns_nxdomain: Counter = field(default_factory=Counter)
    http_requests: list = field(default_factory=list)
    tls_sni: Counter = field(default_factory=Counter)
    arp_table: dict = field(default_factory=lambda: defaultdict(set))
    dhcp_messages: list = field(default_factory=list)
    malformed: int = 0

    # ------------------------------------------------------------------ #
    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)

    @property
    def avg_packet_size(self) -> float:
        return self.total_bytes / self.total_packets if self.total_packets else 0.0

    @property
    def packets_per_sec(self) -> float:
        return self.total_packets / self.duration if self.duration else float(self.total_packets)

    @property
    def bits_per_sec(self) -> float:
        return self.total_bytes * 8 / self.duration if self.duration else 0.0

    @property
    def unique_hosts(self) -> int:
        return len(set(self.host_sent) | set(self.host_recv))

    def top_talkers(self, n: int = 10) -> list[tuple[str, int, int, int]]:
        """(host, bytes_sent, bytes_received, packets) ordered by total bytes."""
        hosts = set(self.host_sent) | set(self.host_recv)
        rows = [(h, self.host_sent[h], self.host_recv[h], self.host_packets[h]) for h in hosts]
        rows.sort(key=lambda r: r[1] + r[2], reverse=True)
        return rows[:n]

    def top_conversations(self, n: int = 10) -> list[Conversation]:
        return sorted(self.conversations.values(), key=lambda c: c.bytes, reverse=True)[:n]

    def timeline(self, bucket: float = 1.0) -> list[tuple[float, int, int]]:
        """(seconds_from_start, packets, bytes) for every time bucket."""
        if not self.packets:
            return []
        n_buckets = int(self.duration // bucket) + 1
        pk, by = [0] * n_buckets, [0] * n_buckets
        for p in self.packets:
            i = min(n_buckets - 1, int((p.timestamp - self.start) // bucket))
            pk[i] += 1
            by[i] += p.length
        return [(i * bucket, pk[i], by[i]) for i in range(n_buckets)]

    def summary(self) -> dict:
        return {
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "duration_s": round(self.duration, 3),
            "avg_packet_size": round(self.avg_packet_size, 1),
            "packets_per_sec": round(self.packets_per_sec, 2),
            "bits_per_sec": round(self.bits_per_sec, 1),
            "unique_hosts": self.unique_hosts,
            "conversations": len(self.conversations),
            "protocols": dict(self.protocol_packets.most_common()),
            "network_layer": dict(self.network_layer.most_common()),
            "transport_layer": dict(self.transport_layer.most_common()),
            "tcp_flags": dict(self.tcp_flags.most_common()),
            "top_dst_ports": self.dst_ports.most_common(10),
            "dns_queries": len(self.dns_queries),
            "http_requests": len(self.http_requests),
            "tls_servers": len(self.tls_sni),
            "malformed": self.malformed,
        }


def _endpoint(ip: str, port: int | None) -> str:
    if port is None:
        return ip
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def compute(packets: list[Packet]) -> TrafficStats:
    st = TrafficStats(packets=packets)
    if not packets:
        return st
    st.start = min(p.timestamp for p in packets)
    st.end = max(p.timestamp for p in packets)

    for p in packets:
        st.total_packets += 1
        st.total_bytes += p.length
        st.protocol_packets[p.protocol] += 1
        st.protocol_bytes[p.protocol] += p.length
        if p.network:
            st.network_layer[p.network] += 1
        if p.transport:
            st.transport_layer[p.transport] += 1
        if p.malformed:
            st.malformed += 1

        for lo, hi in SIZE_BUCKETS:
            if lo <= p.length <= hi:
                st.size_hist[(lo, hi)] += 1
                break

        src, dst = p.source, p.destination
        if src:
            st.host_sent[src] += p.length
            st.host_packets[src] += 1
        if dst:
            st.host_recv[dst] += p.length

        if p.transport == "TCP":
            for flag in ("S", "A", "F", "R", "P"):
                if flag in p.tcp_flags:
                    st.tcp_flags[{"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH"}[flag]] += 1
            if p.is_syn:
                st.dst_ports[p.dst_port] += 1   # count connection attempts per port
        elif p.transport == "UDP" and p.dst_port is not None and not p.dns_response:
            st.dst_ports[p.dst_port] += 1
        if p.service:
            st.services[p.service] += 1

        _add_conversation(st, p)

        if p.protocol in ("DNS", "mDNS") and p.dns_query:
            if p.dns_response:
                st.dns_answers[p.dns_query].update(p.dns_answers)
                if p.dns_rcode == 3:
                    st.dns_nxdomain[p.dns_query] += 1
            else:
                st.dns_queries[(p.dns_query, p.dns_qtype)] += 1
        if p.http_method:
            st.http_requests.append(p)
        if p.tls_sni:
            st.tls_sni[p.tls_sni] += 1
        if p.network == "ARP" and p.arp_sender_ip and p.arp_sender_ip != "0.0.0.0":
            st.arp_table[p.arp_sender_ip].add(p.arp_sender_mac)
        if p.dhcp_type:
            st.dhcp_messages.append(p)
    return st


def _add_conversation(st: TrafficStats, p: Packet) -> None:
    if not p.src_ip or not p.transport:
        return
    a, b = _endpoint(p.src_ip, p.src_port), _endpoint(p.dst_ip, p.dst_port)
    key = (p.transport,) + tuple(sorted((a, b)))
    conv = st.conversations.get(key)
    if conv is None:
        conv = Conversation(proto=p.transport, a=a, b=b, start=p.timestamp, service=p.service)
        st.conversations[key] = conv
    conv.packets += 1
    conv.bytes += p.length
    if a == conv.a:
        conv.a_to_b_bytes += p.length
    else:
        conv.b_to_a_bytes += p.length
    conv.end = p.timestamp
    if p.transport == "TCP":
        conv.syn |= p.is_syn
        conv.synack |= p.is_synack
        conv.fin |= "F" in p.tcp_flags
        conv.rst |= "R" in p.tcp_flags
