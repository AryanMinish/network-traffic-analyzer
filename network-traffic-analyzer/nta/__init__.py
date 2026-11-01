"""
NTA - Network Traffic Analyzer
A packet capture and protocol analysis tool written in pure Python.

    from nta import analyze_file
    result = analyze_file("samples/lab_traffic.pcap")
    print(result.stats.summary())
    for alert in result.alerts:
        print(alert.severity, alert.description)
"""

from __future__ import annotations

from dataclasses import dataclass

from .decoder import Packet, decode
from .detector import Alert, Thresholds, detect
from .pcap import RawPacket, read_packets
from .stats import TrafficStats, compute

__version__ = "1.0.0"
__author__ = "Aryan Minish Kanjiraparambil"

__all__ = ["analyze_file", "analyze_raw", "AnalysisResult", "Packet", "Alert",
           "Thresholds", "TrafficStats", "decode", "detect", "compute", "read_packets"]


@dataclass
class AnalysisResult:
    source: str
    packets: list[Packet]
    stats: TrafficStats
    alerts: list[Alert]


def analyze_raw(raw_packets, source: str = "capture", thresholds: Thresholds | None = None) -> AnalysisResult:
    packets = [decode(raw, i) for i, raw in enumerate(raw_packets, start=1)]
    return AnalysisResult(source, packets, compute(packets), detect(packets, thresholds))


def analyze_file(path: str, thresholds: Thresholds | None = None) -> AnalysisResult:
    return analyze_raw(read_packets(path), source=path, thresholds=thresholds)
