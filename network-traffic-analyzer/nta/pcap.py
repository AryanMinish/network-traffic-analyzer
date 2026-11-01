"""
Reading and writing packet capture files using only the Python standard library.

Supports:
  * classic libpcap files (.pcap) - microsecond and nanosecond variants, both byte orders
  * pcapng files (.pcapng) - the default format saved by Wireshark

Each packet is returned as a RawPacket(timestamp, linktype, data, wire_len).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

# Link-layer header types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_NULL = 0          # BSD loopback
LINKTYPE_ETHERNET = 1      # Ethernet II
LINKTYPE_RAW = 101         # Raw IPv4 / IPv6, no link header
LINKTYPE_LINUX_SLL = 113   # Linux "cooked" capture

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A


@dataclass
class RawPacket:
    timestamp: float   # seconds since the Unix epoch
    linktype: int      # link-layer header type of `data`
    data: bytes        # captured bytes
    wire_len: int      # original length of the packet on the wire


class PcapError(Exception):
    """Raised when a capture file cannot be parsed."""


def read_packets(path: str) -> Iterator[RawPacket]:
    """Yield every packet in a .pcap or .pcapng file."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            raise PcapError("File is too small to be a capture file")
        fh.seek(0)
        magic_le = struct.unpack("<I", head)[0]
        if magic_le == PCAPNG_SHB:
            yield from _read_pcapng(fh)
        else:
            yield from _read_pcap(fh)


# --------------------------------------------------------------------------- #
# classic pcap
# --------------------------------------------------------------------------- #
def _read_pcap(fh: BinaryIO) -> Iterator[RawPacket]:
    header = fh.read(24)
    if len(header) < 24:
        raise PcapError("Truncated pcap global header")

    for endian in ("<", ">"):
        magic = struct.unpack(endian + "I", header[:4])[0]
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            break
    else:
        raise PcapError("Not a pcap/pcapng file (unknown magic number)")

    divisor = 1e6 if magic == PCAP_MAGIC_US else 1e9
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", header[4:24])
    record = struct.Struct(endian + "IIII")

    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl_len, orig_len = record.unpack(rec)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            return  # truncated final packet
        yield RawPacket(ts_sec + ts_frac / divisor, linktype, data, orig_len)


# --------------------------------------------------------------------------- #
# pcapng
# --------------------------------------------------------------------------- #
def _read_pcapng(fh: BinaryIO) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, ticks_per_second)

    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        block_type = struct.unpack(endian + "I", head[:4])[0]

        if block_type == PCAPNG_SHB:
            # Byte-order magic tells us the endianness of this section
            bom = fh.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            block_len = struct.unpack(endian + "I", head[4:8])[0]
            fh.read(block_len - 12)
            interfaces = []
            continue

        block_len = struct.unpack(endian + "I", head[4:8])[0]
        if block_len < 12:
            raise PcapError("Corrupt pcapng block length")
        body = fh.read(block_len - 8)
        body = body[:-4]  # trailing copy of the block length

        if block_type == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _if_tsresol(body[8:], endian)))
        elif block_type == 6:  # Enhanced Packet Block
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            linktype, tps = interfaces[if_id] if if_id < len(interfaces) else (LINKTYPE_ETHERNET, 1e6)
            ticks = (ts_hi << 32) | ts_lo
            yield RawPacket(ticks / tps, linktype, body[20:20 + cap_len], orig_len)
        elif block_type == 3:  # Simple Packet Block (no timestamp)
            orig_len = struct.unpack(endian + "I", body[:4])[0]
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield RawPacket(0.0, linktype, body[4:4 + orig_len], orig_len)
        # other block types (statistics, name resolution, ...) are skipped


def _if_tsresol(options: bytes, endian: str) -> float:
    """Return timestamp ticks per second from IDB options (default: microseconds)."""
    i = 0
    while i + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[i:i + 4])
        if code == 0:
            break
        value = options[i + 4:i + 4 + length]
        if code == 9 and value:  # if_tsresol
            v = value[0]
            return float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
        i += 4 + length + ((4 - length % 4) % 4)
    return 1e6


# --------------------------------------------------------------------------- #
# writer
# --------------------------------------------------------------------------- #
class PcapWriter:
    """Write packets to a classic microsecond-resolution pcap file."""

    def __init__(self, path: str, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 65535):
        self._fh = open(path, "wb")
        self._fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, linktype))

    def write(self, timestamp: float, data: bytes, wire_len: int | None = None) -> None:
        sec = int(timestamp)
        usec = int(round((timestamp - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self._fh.write(struct.pack("<IIII", sec, usec, len(data), wire_len or len(data)))
        self._fh.write(data)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
