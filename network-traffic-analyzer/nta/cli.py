"""
Command-line interface.

  python -m nta analyze  samples/lab_traffic.pcap --out output
  python -m nta packets  samples/lab_traffic.pcap --protocol DNS -n 20
  sudo python -m nta capture -i eth0 -c 500 -t 30 -w my_capture.pcap
  python -m nta dashboard            # web dashboard on http://127.0.0.1:5000
  python -m nta interfaces
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, analyze_file, analyze_raw
from .detector import Thresholds


def _thresholds(args) -> Thresholds:
    th = Thresholds()
    if getattr(args, "scan_ports", None):
        th.portscan_ports = args.scan_ports
    if getattr(args, "flood_syns", None):
        th.synflood_syns = args.flood_syns
    return th


def _outputs(result, args) -> None:
    from . import report
    print(report.console_report(result, top=args.top))
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        files = report.write_csv(result, args.out)
        files.append(report.write_json(result, os.path.join(args.out, "summary.json")))
        try:
            files += list(report.write_charts(result, args.out).values())
            charts = True
        except ImportError:
            print("  (matplotlib not installed - skipping charts)")
            charts = False
        files.append(report.write_html(result, os.path.join(args.out, "report.html"), charts=charts))
        print(f"\n  Saved {len(files)} files to {args.out.rstrip('/')}/")
        for f in files:
            print(f"    • {os.path.basename(f)}")


def cmd_analyze(args) -> int:
    if not os.path.exists(args.file):
        print(f"error: file not found: {args.file}", file=sys.stderr)
        return 1
    result = analyze_file(args.file, _thresholds(args))
    _outputs(result, args)
    return 0


def cmd_packets(args) -> int:
    from . import report
    result = analyze_file(args.file)
    print(report.packet_list(result, limit=args.n, protocol=args.protocol))
    return 0


def cmd_capture(args) -> int:
    from .capture import CaptureError, capture
    print(f"Capturing on {args.interface or 'default interface'} "
          f"(max {args.count} packets or {args.timeout:.0f} s) - press Ctrl+C to stop early ...")
    seen = [0]

    def tick(_raw):
        seen[0] += 1
        if seen[0] % 25 == 0:
            print(f"\r  {seen[0]} packets", end="", flush=True)

    try:
        raws = capture(args.interface, args.count, args.timeout, args.write, on_packet=tick)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"\r  Captured {len(raws)} packets" + (f" → saved to {args.write}" if args.write else "") + "\n")
    if not raws:
        return 0
    result = analyze_raw(raws, source=args.write or f"live:{args.interface}", thresholds=_thresholds(args))
    _outputs(result, args)
    return 0


def cmd_dashboard(args) -> int:
    try:
        from .web import create_app
    except ImportError:
        print("error: the dashboard needs Flask - run: pip install flask", file=sys.stderr)
        return 1
    app = create_app()
    print(f"Dashboard running on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def cmd_interfaces(_args) -> int:
    from .capture import list_interfaces
    names = list_interfaces()
    print("\n".join(f"  {n}" for n in names) if names else "  (could not list interfaces)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nta", description="Network Traffic Analyzer - packet capture "
                                "and protocol analysis in pure Python")
    p.add_argument("--version", action="version", version=f"nta {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("--out", "-o", help="folder for CSV/JSON/chart/HTML reports")
        sp.add_argument("--top", type=int, default=8, help="rows to show in each table (default 8)")
        sp.add_argument("--scan-ports", type=int, help="port-scan threshold (distinct ports, default 20)")
        sp.add_argument("--flood-syns", type=int, help="SYN-flood threshold (SYNs in 10 s, default 200)")

    a = sub.add_parser("analyze", help="analyse a .pcap / .pcapng file")
    a.add_argument("file")
    add_common(a)
    a.set_defaults(func=cmd_analyze)

    k = sub.add_parser("packets", help="print a Wireshark-style packet list")
    k.add_argument("file")
    k.add_argument("-n", type=int, default=30, help="number of packets to show")
    k.add_argument("--protocol", "-p", help="only show this protocol (e.g. DNS, TLS, ARP)")
    k.set_defaults(func=cmd_packets)

    c = sub.add_parser("capture", help="capture live traffic (needs root/admin)")
    c.add_argument("-i", "--interface", help="interface name (Linux) or local IP (Windows)")
    c.add_argument("-c", "--count", type=int, default=500, help="stop after N packets (default 500)")
    c.add_argument("-t", "--timeout", type=float, default=30, help="stop after T seconds (default 30)")
    c.add_argument("-w", "--write", help="also save the capture to this .pcap file")
    add_common(c)
    c.set_defaults(func=cmd_capture)

    d = sub.add_parser("dashboard", help="start the web dashboard (needs Flask)")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=5000)
    d.set_defaults(func=cmd_dashboard)

    i = sub.add_parser("interfaces", help="list network interfaces")
    i.set_defaults(func=cmd_interfaces)
    return p


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt":
        os.system("")  # enables ANSI colour codes in the Windows console
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # box-drawing characters on Windows consoles
        except (ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
