"""
Rule-based detection of suspicious traffic patterns.

Each rule is a small, explainable heuristic with a configurable threshold - the
same idea used by signature/threshold IDS tools such as Snort or Zeek, kept
deliberately simple so every alert can be traced back to the packets behind it.

Rules
  1. TCP port scan        one source sends SYNs to many ports on one host
  2. SYN flood            many SYNs to one service, few completed handshakes
  3. ICMP flood           burst of echo requests to one host
  4. ARP spoofing         one IP address claimed by more than one MAC address
  5. DNS tunnelling       unusually long / random-looking DNS names under one domain
  6. Clear-text login     HTTP Basic auth, Telnet or FTP credentials sent unencrypted
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

from .decoder import Packet

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Thresholds:
    portscan_ports: int = 20          # distinct ports probed ...
    portscan_window: float = 60.0     # ... within this many seconds
    synflood_syns: int = 200          # SYNs to one host:port ...
    synflood_window: float = 10.0     # ... within this many seconds
    synflood_max_completion: float = 0.2   # and < 20 % answered by the client's ACK
    icmp_flood_pkts: int = 100        # echo requests to one host ...
    icmp_flood_window: float = 10.0   # ... within this many seconds
    dns_name_length: int = 50         # query names longer than this are suspicious
    dns_entropy: float = 3.5          # Shannon entropy (bits/char) of the longest label
    dns_min_queries: int = 10         # long queries to one parent domain before alerting


@dataclass
class Alert:
    rule: str
    severity: str
    source: str
    target: str
    first_seen: float
    last_seen: float
    count: int
    description: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
def _max_in_window(times: list[float], window: float) -> tuple[int, float, float]:
    """Largest number of events inside any sliding window (two-pointer scan)."""
    times = sorted(times)
    best, best_start, best_end, lo = 0, 0.0, 0.0, 0
    for hi, t in enumerate(times):
        while t - times[lo] > window:
            lo += 1
        if hi - lo + 1 > best:
            best, best_start, best_end = hi - lo + 1, times[lo], t
    return best, best_start, best_end


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


# --------------------------------------------------------------------------- #
def detect(packets: list[Packet], th: Thresholds | None = None) -> list[Alert]:
    th = th or Thresholds()
    alerts: list[Alert] = []
    alerts += _port_scan(packets, th)
    alerts += _syn_flood(packets, th)
    alerts += _icmp_flood(packets, th)
    alerts += _arp_spoof(packets)
    alerts += _dns_tunnel(packets, th)
    alerts += _cleartext(packets)
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen))
    return alerts


def _port_scan(packets: list[Packet], th: Thresholds) -> list[Alert]:
    probes: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    open_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    for p in packets:
        if p.transport != "TCP":
            continue
        if p.is_syn:
            probes[(p.src_ip, p.dst_ip)].append((p.timestamp, p.dst_port))
        elif p.is_synack:
            open_ports[(p.dst_ip, p.src_ip)].add(p.src_port)

    alerts = []
    for (src, dst), events in probes.items():
        events.sort()
        lo, best, best_span = 0, set(), (0.0, 0.0)
        for hi in range(len(events)):
            while events[hi][0] - events[lo][0] > th.portscan_window:
                lo += 1
            ports = {port for _, port in events[lo:hi + 1]}
            if len(ports) > len(best):
                best, best_span = ports, (events[lo][0], events[hi][0])
        if len(best) >= th.portscan_ports:
            found_open = sorted(open_ports[(src, dst)] & best)
            alerts.append(Alert(
                rule="TCP port scan", severity="HIGH", source=src, target=dst,
                first_seen=best_span[0], last_seen=best_span[1], count=len(best),
                description=(f"{src} probed {len(best)} different TCP ports on {dst} in "
                             f"{best_span[1] - best_span[0]:.1f} s (SYN scan). "
                             f"Open ports revealed: {', '.join(map(str, found_open)) or 'none'}."),
                evidence={"ports_probed": len(best), "port_range": [min(best), max(best)],
                          "open_ports": found_open}))
    return alerts


def _syn_flood(packets: list[Packet], th: Thresholds) -> list[Alert]:
    syns: dict[tuple[str, int], list[float]] = defaultdict(list)
    sources: dict[tuple[str, int], set[str]] = defaultdict(set)
    # handshakes completed = client ACK that follows a SYN on the same 4-tuple
    pending: set[tuple] = set()
    completed: Counter = Counter()
    for p in packets:
        if p.transport != "TCP":
            continue
        key4 = (p.src_ip, p.src_port, p.dst_ip, p.dst_port)
        if p.is_syn:
            syns[(p.dst_ip, p.dst_port)].append(p.timestamp)
            sources[(p.dst_ip, p.dst_port)].add(p.src_ip)
            pending.add(key4)
        elif p.tcp_flags == "A" and key4 in pending:
            pending.discard(key4)
            completed[(p.dst_ip, p.dst_port)] += 1

    alerts = []
    for target, times in syns.items():
        count, t0, t1 = _max_in_window(times, th.synflood_window)
        if count < th.synflood_syns:
            continue
        ratio = completed[target] / len(times)
        if ratio > th.synflood_max_completion:
            continue
        dst, port = target
        alerts.append(Alert(
            rule="SYN flood (DoS)", severity="CRITICAL", source=f"{len(sources[target])} sources",
            target=f"{dst}:{port}", first_seen=t0, last_seen=t1, count=count,
            description=(f"{count} SYN packets hit {dst}:{port} within {t1 - t0:.1f} s from "
                         f"{len(sources[target])} different source addresses; only "
                         f"{ratio:.1%} of handshakes were completed (half-open connections)."),
            evidence={"syn_count": count, "unique_sources": len(sources[target]),
                      "completion_ratio": round(ratio, 3)}))
    return alerts


def _icmp_flood(packets: list[Packet], th: Thresholds) -> list[Alert]:
    echo: dict[str, list[float]] = defaultdict(list)
    senders: dict[str, Counter] = defaultdict(Counter)
    for p in packets:
        if p.transport == "ICMP" and p.icmp_type == 8:
            echo[p.dst_ip].append(p.timestamp)
            senders[p.dst_ip][p.src_ip] += 1
    alerts = []
    for dst, times in echo.items():
        count, t0, t1 = _max_in_window(times, th.icmp_flood_window)
        if count >= th.icmp_flood_pkts:
            top = senders[dst].most_common(1)[0][0]
            rate = count / max(t1 - t0, 0.001)
            alerts.append(Alert(
                rule="ICMP flood", severity="MEDIUM", source=top, target=dst,
                first_seen=t0, last_seen=t1, count=count,
                description=f"{count} ICMP echo requests sent to {dst} in {t1 - t0:.1f} s "
                            f"(~{rate:.0f} per second), mainly from {top}.",
                evidence={"echo_requests": count, "rate_per_sec": round(rate, 1)}))
    return alerts


def _arp_spoof(packets: list[Packet]) -> list[Alert]:
    claims: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for p in packets:
        if p.network == "ARP" and p.arp_op == 2 and p.arp_sender_ip:
            claims[p.arp_sender_ip][p.arp_sender_mac].append(p.timestamp)
    alerts = []
    for ip, macs in claims.items():
        if len(macs) < 2:
            continue
        # the MAC that appeared first is assumed legitimate; later ones are suspects
        ordered = sorted(macs.items(), key=lambda kv: min(kv[1]))
        original = ordered[0][0]
        for mac, times in ordered[1:]:
            alerts.append(Alert(
                rule="ARP spoofing", severity="HIGH", source=mac, target=ip,
                first_seen=min(times), last_seen=max(times), count=len(times),
                description=(f"IP {ip} was previously at {original} but {len(times)} ARP replies "
                             f"now claim it is at {mac} - possible man-in-the-middle (ARP cache poisoning)."),
                evidence={"original_mac": original, "spoofed_mac": mac, "replies": len(times)}))
    return alerts


def _parent_domain(name: str) -> str:
    parts = name.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def _dns_tunnel(packets: list[Packet], th: Thresholds) -> list[Alert]:
    groups: dict[tuple[str, str], list[Packet]] = defaultdict(list)
    for p in packets:
        if p.protocol == "DNS" and p.dns_query and not p.dns_response:
            longest = max(p.dns_query.split("."), key=len)
            if len(p.dns_query) > th.dns_name_length or (shannon_entropy(longest) > th.dns_entropy and len(longest) > 20):
                groups[(p.src_ip, _parent_domain(p.dns_query))].append(p)
    alerts = []
    for (src, domain), pkts in groups.items():
        if len(pkts) < th.dns_min_queries:
            continue
        avg_len = sum(len(p.dns_query) for p in pkts) / len(pkts)
        unique = len({p.dns_query for p in pkts})
        alerts.append(Alert(
            rule="DNS tunnelling suspected", severity="MEDIUM", source=src, target=domain,
            first_seen=pkts[0].timestamp, last_seen=pkts[-1].timestamp, count=len(pkts),
            description=(f"{src} sent {len(pkts)} DNS queries with long, random-looking names under "
                         f"'{domain}' ({unique} unique, average {avg_len:.0f} characters). "
                         f"Data may be hidden inside DNS lookups."),
            evidence={"queries": len(pkts), "unique_names": unique, "avg_length": round(avg_len, 1),
                      "example": pkts[0].dns_query}))
    return alerts


def _cleartext(packets: list[Packet]) -> list[Alert]:
    seen: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for p in packets:
        if p.http_basic_auth:
            seen[("HTTP Basic auth", p.src_ip, f"{p.http_host or p.dst_ip}")].append(p.timestamp)
        elif p.transport == "TCP" and p.dst_port in (21, 23) and p.payload_len and p.is_syn is False:
            name = "FTP login" if p.dst_port == 21 else "Telnet session"
            seen[(name, p.src_ip, f"{p.dst_ip}:{p.dst_port}")].append(p.timestamp)
    alerts = []
    for (kind, src, dst), times in seen.items():
        alerts.append(Alert(
            rule="Clear-text credentials", severity="LOW", source=src, target=dst,
            first_seen=min(times), last_seen=max(times), count=len(times),
            description=(f"{kind} from {src} to {dst} sends the username and password without "
                         f"encryption - anyone on the path can read them. Use HTTPS/SSH/SFTP instead. "
                         f"(Credentials are not stored by this tool.)"),
            evidence={"type": kind, "occurrences": len(times)}))
    return alerts
