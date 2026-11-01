"""
Live packet capture with raw sockets (no libpcap / Npcap needed).

  * Linux   - AF_PACKET socket: full Ethernet frames from one interface
  * Windows - AF_INET raw socket with SIO_RCVALL: IP packets (no Ethernet header)
  * macOS   - raw capture needs BPF devices; capture with Wireshark/tcpdump to a
              .pcap file and analyse it with `nta analyze` instead

Capturing traffic requires administrator / root privileges. Only capture on
networks you own or are explicitly authorised to monitor.
"""

from __future__ import annotations

import platform
import socket
import time
from typing import Callable

from .pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, PcapWriter, RawPacket

ETH_P_ALL = 0x0003


class CaptureError(Exception):
    pass


def list_interfaces() -> list[str]:
    try:
        return [name for _, name in socket.if_nameindex()]
    except (AttributeError, OSError):
        return []


def _open_socket(interface: str | None) -> tuple[socket.socket, int]:
    system = platform.system()
    try:
        if system == "Linux":
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
            if interface:
                sock.bind((interface, 0))
            return sock, LINKTYPE_ETHERNET
        if system == "Windows":
            host = interface or socket.gethostbyname(socket.gethostname())
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return sock, LINKTYPE_RAW
    except PermissionError as exc:
        raise CaptureError("Permission denied - run as root (Linux) or as Administrator (Windows).") from exc
    except OSError as exc:
        raise CaptureError(f"Could not open interface {interface!r}: {exc}") from exc
    raise CaptureError(f"Live capture is not supported on {system}. Capture with Wireshark "
                       f"or tcpdump and run: python -m nta analyze <file.pcap>")


def capture(interface: str | None = None, count: int = 500, timeout: float = 30.0,
            write_to: str | None = None,
            on_packet: Callable[[RawPacket], None] | None = None) -> list[RawPacket]:
    """Capture until `count` packets or `timeout` seconds, whichever comes first."""
    sock, linktype = _open_socket(interface)
    writer = PcapWriter(write_to, linktype) if write_to else None
    packets: list[RawPacket] = []
    deadline = time.time() + timeout
    try:
        while len(packets) < count:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            # On the Linux loopback interface every packet is seen twice (sent + received);
            # drop the outgoing copy, exactly like tcpdump/libpcap do.
            if linktype == LINKTYPE_ETHERNET and len(addr) > 2 and addr[0] == "lo" \
                    and addr[2] == getattr(socket, "PACKET_OUTGOING", 4):
                continue
            raw = RawPacket(time.time(), linktype, data, len(data))
            packets.append(raw)
            if writer:
                writer.write(raw.timestamp, raw.data, raw.wire_len)
            if on_packet:
                on_packet(raw)
    except KeyboardInterrupt:
        pass
    finally:
        if platform.system() == "Windows":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        sock.close()
        if writer:
            writer.close()
    return packets
