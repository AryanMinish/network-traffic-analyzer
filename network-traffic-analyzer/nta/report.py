"""
Output layer: console report, CSV / JSON exports, charts and a self-contained
HTML dashboard report.

Charts need matplotlib (pip install matplotlib); everything else is standard library.
"""

from __future__ import annotations

import base64
import csv
import html
import io
import json
import os
import sys
import textwrap
from datetime import datetime

from . import AnalysisResult, __version__

# ---- palette (validated categorical slots + status colours) ---------------- #
INK, INK_2, INK_3 = "#0b0b0b", "#52514e", "#8a8984"
SURFACE, GRID = "#fcfcfb", "#e6e5e0"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
STATUS = {"CRITICAL": "#d03b3b", "HIGH": "#ec835a", "MEDIUM": "#fab219", "LOW": "#2a78d6"}
ICON = {"CRITICAL": "■", "HIGH": "▲", "MEDIUM": "●", "LOW": "◆"}


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def human_rate(bps: float) -> str:
    for unit in ("bps", "kbps", "Mbps", "Gbps"):
        if bps < 1000 or unit == "Gbps":
            return f"{bps:,.1f} {unit}"
        bps /= 1000
    return f"{bps:.1f} Gbps"


def fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# console
# --------------------------------------------------------------------------- #
class _C:
    """ANSI colours, disabled automatically when output is not a terminal."""
    def __init__(self, enabled: bool | None):
        e = enabled if enabled is not None else (sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR")))
        self.B = "\033[1m" if e else ""
        self.DIM = "\033[2m" if e else ""
        self.CYAN = "\033[36m" if e else ""
        self.GREEN = "\033[32m" if e else ""
        self.YEL = "\033[33m" if e else ""
        self.RED = "\033[31m" if e else ""
        self.MAG = "\033[35m" if e else ""
        self.X = "\033[0m" if e else ""


def table(headers: list[str], rows: list[list], align: str | None = None) -> str:
    cols = [list(map(str, col)) for col in zip(headers, *rows)] if rows else [[h] for h in headers]
    widths = [max(len(v) for v in col) for col in cols]
    align = align or "l" * len(headers)

    def fmt(vals):
        out = []
        for v, w, a in zip(map(str, vals), widths, align):
            out.append(v.rjust(w) if a == "r" else v.ljust(w))
        return "  " + "  ".join(out)

    line = "  " + "  ".join("─" * w for w in widths)
    return "\n".join([fmt(headers), line] + [fmt(r) for r in rows])


def console_report(result: AnalysisResult, top: int = 8, color: bool | None = None) -> str:
    c = _C(color)
    st = result.stats
    out = []

    def h(title):
        out.append(f"\n{c.B}{c.CYAN}▌ {title}{c.X}")

    out.append(f"{c.B}NETWORK TRAFFIC ANALYZER v{__version__}{c.X}  {c.DIM}— {os.path.basename(result.source)}{c.X}")
    h("Capture summary")
    out.append(table(["Metric", "Value"], [
        ["Packets", f"{st.total_packets:,}"],
        ["Total data", human_bytes(st.total_bytes)],
        ["Capture window", f"{fmt_time(st.start)}  →  {st.duration:.1f} s" if st.total_packets else "-"],
        ["Average rate", f"{st.packets_per_sec:,.1f} packets/s   {human_rate(st.bits_per_sec)}"],
        ["Average packet size", f"{st.avg_packet_size:,.0f} bytes"],
        ["Hosts / conversations", f"{st.unique_hosts:,} host{'s' * (st.unique_hosts != 1)}   "
                                  f"{len(st.conversations):,} conversation{'s' * (len(st.conversations) != 1)}"],
    ]))

    h("Protocol hierarchy")
    rows = []
    for proto, n in st.protocol_packets.most_common():
        pct = 100 * n / st.total_packets
        bar = "█" * max(1, round(pct / 2.5))
        rows.append([proto, f"{n:,}", f"{pct:5.1f}%", human_bytes(st.protocol_bytes[proto]), f"{c.GREEN}{bar}{c.X}"])
    out.append(table(["Protocol", "Packets", "Share", "Bytes", ""], rows, "lrrrl"))
    layers = (f"  {c.DIM}Network: " + ", ".join(f"{k} {v:,}" for k, v in st.network_layer.most_common())
              + "   Transport: " + ", ".join(f"{k} {v:,}" for k, v in st.transport_layer.most_common()) + c.X)
    out.append(layers)

    h(f"Top {top} talkers (by bytes)")
    out.append(table(["Host", "Sent", "Received", "Packets"],
                     [[hst, human_bytes(s), human_bytes(r), f"{p:,}"] for hst, s, r, p in st.top_talkers(top)],
                     "lrrr"))

    h(f"Top {top} conversations")
    out.append(table(["Proto", "Endpoint A", "Endpoint B", "Service", "Packets", "Bytes", "Duration", "State"],
                     [[cv.proto, cv.a, cv.b, cv.service or "-", f"{cv.packets:,}", human_bytes(cv.bytes),
                       f"{cv.duration:.2f} s", cv.state] for cv in st.top_conversations(top)],
                     "llllrrrl"))

    h("Destination ports (connection attempts)")
    from .decoder import SERVICES
    out.append(table(["Port", "Service", "Attempts"],
                     [[p, SERVICES.get(p, "-"), f"{n:,}"] for p, n in st.dst_ports.most_common(top)], "rlr"))

    h("Application layer")
    dns_rows = [[q, t, n, ", ".join(sorted(st.dns_answers.get(q, [])))[:40] or ("NXDOMAIN" if st.dns_nxdomain.get(q) else "-")]
                for (q, t), n in st.dns_queries.most_common(top)]
    out.append(f"  {c.B}DNS lookups{c.X} ({len(st.dns_queries)} unique names)")
    if dns_rows:
        out.append(table(["Query", "Type", "Count", "Answer"], [[r[0][:48]] + r[1:] for r in dns_rows], "llrl"))
    if st.tls_sni:
        sni = ", ".join(f"{s}\u00a0({n})" for s, n in st.tls_sni.most_common(top))  # keep name+count together
        wrapped = textwrap.wrap(sni, width=92)
        out.append(f"\n  {c.B}HTTPS servers (TLS SNI){c.X}")
        out.extend(f"  {line}" for line in wrapped)
    if st.http_requests:
        out.append(f"\n  {c.B}HTTP requests{c.X}")
        out.append(table(["Client", "Method", "Host", "URI"],
                         [[p.src_ip, p.http_method, p.http_host, p.http_uri] for p in st.http_requests[:top]]))
    if st.dhcp_messages:
        out.append(f"\n  {c.B}DHCP{c.X}: " + " → ".join(p.dhcp_type for p in st.dhcp_messages[:8]))

    h(f"Security alerts ({len(result.alerts)})")
    if not result.alerts:
        out.append(f"  {c.GREEN}✔ No suspicious patterns detected with the current thresholds.{c.X}")
    colors = {"CRITICAL": c.RED + c.B, "HIGH": c.RED, "MEDIUM": c.YEL, "LOW": c.CYAN}
    for a in result.alerts:
        t0 = datetime.fromtimestamp(a.first_seen).strftime("%H:%M:%S")
        out.append(f"  {colors[a.severity]}{ICON[a.severity]} {a.severity:<8}{c.X} {c.B}{a.rule}{c.X}  "
                   f"{c.DIM}{t0}  {a.source} → {a.target}{c.X}")
        for line in textwrap.wrap(a.description, width=96):
            out.append(f"             {line}")
    return "\n".join(out) + "\n"


def packet_list(result: AnalysisResult, limit: int = 30, protocol: str | None = None,
                color: bool | None = None) -> str:
    """Wireshark-style packet list."""
    c = _C(color)
    pk = [p for p in result.packets if not protocol or p.protocol.lower() == protocol.lower()]
    t0 = result.stats.start
    rows = [[p.number, f"{p.timestamp - t0:.6f}", p.source[:22], p.destination[:22], p.protocol,
             p.length, p.info[:70]] for p in pk[:limit]]
    head = f"{c.B}{len(pk):,} packets{c.X}" + (f" matching '{protocol}'" if protocol else "")
    return head + "\n" + table(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"],
                               rows, "rrlllrl") + "\n"


# --------------------------------------------------------------------------- #
# CSV / JSON
# --------------------------------------------------------------------------- #
def write_csv(result: AnalysisResult, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    st, t0, files = result.stats, result.stats.start, []

    def save(name, header, rows):
        path = os.path.join(out_dir, name)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)
        files.append(path)

    save("packets.csv", ["no", "time", "source", "destination", "protocol", "length", "src_port",
                         "dst_port", "tcp_flags", "ttl", "info"],
         [[p.number, round(p.timestamp - t0, 6), p.source, p.destination, p.protocol, p.length,
           p.src_port or "", p.dst_port or "", p.tcp_flags, p.ttl or "", p.info] for p in result.packets])
    save("conversations.csv", ["protocol", "endpoint_a", "endpoint_b", "service", "packets", "bytes",
                               "bytes_a_to_b", "bytes_b_to_a", "start", "duration_s", "state"],
         [[cv.proto, cv.a, cv.b, cv.service, cv.packets, cv.bytes, cv.a_to_b_bytes, cv.b_to_a_bytes,
           round(cv.start - t0, 3), round(cv.duration, 3), cv.state]
          for cv in sorted(st.conversations.values(), key=lambda x: x.bytes, reverse=True)])
    save("dns_queries.csv", ["query", "type", "count", "answers", "nxdomain"],
         [[q, t, n, " ".join(sorted(st.dns_answers.get(q, []))), st.dns_nxdomain.get(q, 0)]
          for (q, t), n in st.dns_queries.most_common()])
    save("alerts.csv", ["severity", "rule", "source", "target", "first_seen", "last_seen", "count", "description"],
         [[a.severity, a.rule, a.source, a.target, fmt_time(a.first_seen), fmt_time(a.last_seen), a.count,
           a.description] for a in result.alerts])
    return files


def write_json(result: AnalysisResult, path: str) -> str:
    st = result.stats
    data = {
        "tool": f"Network Traffic Analyzer {__version__}",
        "source": os.path.basename(result.source),
        "capture_start": fmt_time(st.start) if st.total_packets else None,
        "summary": st.summary(),
        "top_talkers": [{"host": h, "sent": s, "received": r, "packets": p} for h, s, r, p in st.top_talkers(10)],
        "tls_sni": dict(st.tls_sni.most_common()),
        "http_requests": [{"client": p.src_ip, "method": p.http_method, "host": p.http_host,
                           "uri": p.http_uri} for p in st.http_requests],
        "alerts": [a.to_dict() for a in result.alerts],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return path


# --------------------------------------------------------------------------- #
# charts (matplotlib)
# --------------------------------------------------------------------------- #
def _mpl():
    import logging

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
    plt.rcParams.update({
        "font.family": "sans-serif", "font.size": 10,
        "font.sans-serif": ["Arial", "Liberation Sans", "Helvetica", "DejaVu Sans"],
        "axes.edgecolor": GRID, "axes.labelcolor": INK_2, "axes.titlecolor": INK,
        "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
        "axes.titlepad": 12, "xtick.color": INK_2, "ytick.color": INK_2,
        "axes.facecolor": SURFACE, "figure.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.spines.top": False, "axes.spines.right": False, "axes.grid": False,
    })
    return plt


def _finish(fig, path: str | None) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", pad_inches=0.15)
    import matplotlib.pyplot as plt
    plt.close(fig)
    data = buf.getvalue()
    if path:
        with open(path, "wb") as fh:
            fh.write(data)
    return data


def _hbar(ax, labels, values, color, value_fmt):
    y = list(range(len(labels)))[::-1]
    ax.barh(y, values, color=color, height=0.62, edgecolor=SURFACE, linewidth=2)
    ax.set_yticks(y, labels)
    ax.tick_params(axis="y", length=0)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.spines["left"].set_visible(False)
    vmax = max(values) if values else 1
    for yi, v in zip(y, values):
        ax.text(v + vmax * 0.01, yi, value_fmt(v), va="center", ha="left", color=INK_2, fontsize=9)
    ax.set_xlim(0, vmax * 1.16)


def chart_protocols(result: AnalysisResult, path: str | None = None) -> bytes:
    plt = _mpl()
    st = result.stats
    items = st.protocol_packets.most_common(10)
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    _hbar(ax, [k for k, _ in items], [v for _, v in items], BLUE, lambda v: f"{v:,}")
    ax.set_title("Packets by protocol")
    ax.set_xlabel("Packets")
    return _finish(fig, path)


def chart_timeline(result: AnalysisResult, path: str | None = None) -> bytes:
    plt = _mpl()
    st = result.stats
    tl = st.timeline(1.0)
    fig, ax = plt.subplots(figsize=(9.6, 3.4))
    xs = [t for t, _, _ in tl]
    ys = [p for _, p, _ in tl]
    ax.plot(xs, ys, color=BLUE, linewidth=2, solid_capstyle="round")
    ax.fill_between(xs, ys, color=BLUE, alpha=0.08, linewidth=0)
    ymax = max(ys) if ys else 1
    shown = sorted((a for a in result.alerts if a.severity != "LOW"), key=lambda a: a.first_seen)
    for i, a in enumerate(shown):
        x0, x1 = a.first_seen - st.start, max(a.last_seen - st.start, a.first_seen - st.start + 1)
        ax.axvspan(x0, x1, color=STATUS[a.severity], alpha=0.14, linewidth=0)
        label = a.rule.split(" (")[0].replace(" suspected", "")
        ax.text((x0 + x1) / 2, ymax * (1.05 if i % 2 == 0 else 1.17), label, ha="center", va="bottom",
                fontsize=8, color=INK_2)
    ax.set_ylim(0, ymax * 1.3)
    ax.set_xlim(0, max(xs) if xs else 1)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Traffic over time (packets per second) — shaded bands mark alerts")
    ax.set_xlabel("Seconds from start of capture")
    ax.set_ylabel("Packets / s")
    return _finish(fig, path)


def chart_talkers(result: AnalysisResult, path: str | None = None, n: int = 8) -> bytes:
    plt = _mpl()
    rows = result.stats.top_talkers(n)
    labels = [h for h, *_ in rows]
    sent = [s / 1024 for _, s, _, _ in rows]
    recv = [r / 1024 for _, _, r, _ in rows]
    y = list(range(len(labels)))[::-1]
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    ax.barh(y, sent, color=BLUE, height=0.62, edgecolor=SURFACE, linewidth=2, label="Sent")
    ax.barh(y, recv, left=sent, color=ORANGE, height=0.62, edgecolor=SURFACE, linewidth=2, label="Received")
    ax.set_yticks(y, labels)
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    tot = [s + r for s, r in zip(sent, recv)]
    for yi, t in zip(y, tot):
        ax.text(t + max(tot) * 0.01, yi, f"{t:,.0f} KB", va="center", fontsize=9, color=INK_2)
    ax.set_xlim(0, max(tot) * 1.18)
    ax.set_title("Top talkers by data volume")
    ax.set_xlabel("Kilobytes")
    ax.legend(frameon=False, loc="lower right", fontsize=9)
    return _finish(fig, path)


def chart_ports(result: AnalysisResult, path: str | None = None, n: int = 8) -> bytes:
    from .decoder import SERVICES
    plt = _mpl()
    items = result.stats.dst_ports.most_common(n)
    labels = [f"{p} {SERVICES.get(p, '')}".strip() for p, _ in items]
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    _hbar(ax, labels, [v for _, v in items], AQUA, lambda v: f"{v:,}")
    ax.set_title("Destination ports (new connections / datagrams)")
    ax.set_xlabel("Attempts")
    return _finish(fig, path)


def chart_sizes(result: AnalysisResult, path: str | None = None) -> bytes:
    from .stats import SIZE_BUCKETS
    plt = _mpl()
    st = result.stats
    labels = [f"{lo}-{hi}" if hi < 10**8 else f">{lo - 1}" for lo, hi in SIZE_BUCKETS]
    vals = [st.size_hist.get(b, 0) for b in SIZE_BUCKETS]
    while labels and vals[-1] == 0:
        labels.pop(), vals.pop()
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    ax.bar(range(len(vals)), vals, color=BLUE, width=0.7, edgecolor=SURFACE, linewidth=2)
    ax.set_xticks(range(len(vals)), labels)
    ax.tick_params(axis="x", length=0)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for i, v in enumerate(vals):
        ax.text(i, v + max(vals) * 0.015, f"{v:,}", ha="center", va="bottom", fontsize=9, color=INK_2)
    ax.set_ylim(0, max(vals) * 1.15)
    ax.set_title("Packet size distribution")
    ax.set_xlabel("Packet length (bytes)")
    ax.set_ylabel("Packets")
    return _finish(fig, path)


CHARTS = {
    "timeline": chart_timeline,
    "protocols": chart_protocols,
    "talkers": chart_talkers,
    "ports": chart_ports,
    "sizes": chart_sizes,
}


def write_charts(result: AnalysisResult, out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    for name, fn in CHARTS.items():
        path = os.path.join(out_dir, f"chart_{name}.png")
        fn(result, path)
        paths[name] = path
    return paths


# --------------------------------------------------------------------------- #
# HTML dashboard report
# --------------------------------------------------------------------------- #
_CSS = """
:root{color-scheme:light;--bg:#f4f4f1;--card:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--ink3:#8a8984;
--line:#e6e5e0;--accent:#2a78d6;--crit:#d03b3b;--high:#ec835a;--med:#fab219;--low:#2a78d6}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
header{background:#13212e;color:#fff;padding:22px 32px}header h1{margin:0;font-size:22px;letter-spacing:.2px}
header p{margin:4px 0 0;color:#b9c3cc;font-size:13px}main{max-width:1240px;margin:0 auto;padding:24px 32px 48px}
.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-bottom:22px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi b{display:block;font-size:24px;font-weight:650;letter-spacing:-.3px}.kpi span{color:var(--ink2);font-size:12.5px}
h2{font-size:16px;margin:28px 0 12px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;overflow:auto}
.card img{width:100%;display:block}.wide{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--ink2);font-weight:600;
border-bottom:1px solid var(--line);padding:7px 8px;white-space:nowrap}td{padding:6px 8px;border-bottom:1px solid #efeee9;
vertical-align:top}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}tr:last-child td{border-bottom:0}
code{font:12px/1.4 ui-monospace,Consolas,monospace}
.alert{display:flex;gap:14px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin-bottom:10px}
.sev{flex:0 0 96px;font-weight:700;font-size:12px;letter-spacing:.4px;display:flex;align-items:flex-start;gap:6px;padding-top:2px}
.sev i{font-style:normal}.CRITICAL .sev{color:var(--crit)}.HIGH .sev{color:#b85a33}.MEDIUM .sev{color:#9a6b00}.LOW .sev{color:var(--low)}
.alert h3{margin:0 0 2px;font-size:14.5px}.alert p{margin:0;color:var(--ink2)}.meta{color:var(--ink3);font-size:12px;margin-top:4px}
.ok{background:#e9f6e9;border:1px solid #bfe3bf;border-radius:10px;padding:12px 16px;color:#215c21}
footer{color:var(--ink3);font-size:12px;text-align:center;padding:12px}
@media (max-width:900px){.kpis{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}main{padding:16px}}
"""


def _img(png: bytes, alt: str) -> str:
    return f'<img alt="{html.escape(alt)}" src="data:image/png;base64,{base64.b64encode(png).decode()}">'


def html_report(result: AnalysisResult, charts: bool = True) -> str:
    st = result.stats
    e = html.escape
    kpis = [
        (f"{st.total_packets:,}", "Packets captured"),
        (human_bytes(st.total_bytes), "Total data"),
        (f"{st.duration:.1f} s", "Capture duration"),
        (human_rate(st.bits_per_sec), "Average throughput"),
        (f"{len(st.conversations):,}", "Conversations"),
        (f"{len(result.alerts)}", "Security alerts"),
    ]
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Traffic Report – {e(os.path.basename(result.source))}</title><style>{_CSS}</style></head><body>",
             f"<header><h1>Network Traffic Analyzer</h1><p>Report for <b>{e(os.path.basename(result.source))}</b>"
             f" · capture started {e(fmt_time(st.start)) if st.total_packets else '-'}"
             f" · generated {datetime.now():%Y-%m-%d %H:%M}</p></header><main>",
             "<section class='kpis'>" + "".join(f"<div class='kpi'><b>{v}</b><span>{k}</span></div>" for v, k in kpis)
             + "</section>"]

    parts.append(f"<h2>Security alerts ({len(result.alerts)})</h2>")
    if not result.alerts:
        parts.append("<div class='ok'>✔ No suspicious patterns detected with the current thresholds.</div>")
    for a in result.alerts:
        parts.append(f"<div class='alert {a.severity}'><div class='sev'><i>{ICON[a.severity]}</i>{a.severity}</div>"
                     f"<div><h3>{e(a.rule)}</h3><p>{e(a.description)}</p>"
                     f"<div class='meta'>{datetime.fromtimestamp(a.first_seen):%H:%M:%S} – "
                     f"{datetime.fromtimestamp(a.last_seen):%H:%M:%S} · source {e(a.source)} · target {e(a.target)}"
                     f" · {a.count:,} events</div></div></div>")

    if charts:
        try:
            imgs = {name: fn(result) for name, fn in CHARTS.items()}
            parts.append("<h2>Traffic overview</h2><div class='grid'>")
            parts.append(f"<div class='card wide'>{_img(imgs['timeline'], 'Packets per second over time')}</div>")
            for name, alt in (("protocols", "Packets by protocol"), ("talkers", "Top talkers"),
                              ("ports", "Destination ports"), ("sizes", "Packet size distribution")):
                parts.append(f"<div class='card'>{_img(imgs[name], alt)}</div>")
            parts.append("</div>")
        except ImportError:
            parts.append("<p><i>Install matplotlib to include charts.</i></p>")

    def tbl(headers, rows, num=()):
        th = "".join(f"<th class='{'n' if i in num else ''}'>{e(h)}</th>" for i, h in enumerate(headers))
        body = "".join("<tr>" + "".join(f"<td class='{'n' if i in num else ''}'>{e(str(v))}</td>"
                                        for i, v in enumerate(r)) + "</tr>" for r in rows)
        return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"

    parts.append("<h2>Hosts and conversations</h2><div class='grid'>")
    parts.append("<div class='card'>" + tbl(["Host", "Sent", "Received", "Packets"],
                 [[h_, human_bytes(s), human_bytes(r), f"{p:,}"] for h_, s, r, p in st.top_talkers(10)], (1, 2, 3)) + "</div>")
    parts.append("<div class='card'>" + tbl(["Protocol", "Packets", "Share", "Bytes"],
                 [[k, f"{v:,}", f"{100 * v / st.total_packets:.1f}%", human_bytes(st.protocol_bytes[k])]
                  for k, v in st.protocol_packets.most_common()], (1, 2, 3)) + "</div>")
    parts.append("<div class='card wide'>" + tbl(
        ["Proto", "Endpoint A", "Endpoint B", "Service", "Packets", "Bytes", "Duration", "State"],
        [[c.proto, c.a, c.b, c.service or "-", f"{c.packets:,}", human_bytes(c.bytes), f"{c.duration:.2f} s", c.state]
         for c in st.top_conversations(12)], (4, 5, 6)) + "</div></div>")

    parts.append("<h2>Application layer</h2><div class='grid'>")
    parts.append("<div class='card'>" + tbl(["DNS query", "Type", "Count", "Answer"],
                 [[q if len(q) < 44 else q[:41] + "…", t, n,
                   ", ".join(sorted(st.dns_answers.get(q, []))) or ("NXDOMAIN" if st.dns_nxdomain.get(q) else "-")]
                  for (q, t), n in st.dns_queries.most_common(14)], (2,)) + "</div>")
    web_rows = [["HTTPS", s, f"{n} handshake(s)"] for s, n in st.tls_sni.most_common()]
    web_rows += [["HTTP", p.http_host, f"{p.http_method} {p.http_uri}"] for p in st.http_requests]
    parts.append("<div class='card'>" + tbl(["Type", "Server", "Detail"], web_rows) + "</div></div>")

    t0 = st.start
    parts.append("<h2>Packet list (first 40)</h2><div class='card'>" + tbl(
        ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"],
        [[p.number, f"{p.timestamp - t0:.4f}", p.source, p.destination, p.protocol, p.length, p.info]
         for p in result.packets[:40]], (0, 1, 5)) + "</div>")
    parts.append(f"</main><footer>Network Traffic Analyzer v{__version__} · Computer Networks Mini Project · "
                 f"Aryan Minish Kanjiraparambil</footer></body></html>")
    return "".join(parts)


def write_html(result: AnalysisResult, path: str, charts: bool = True) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_report(result, charts))
    return path
