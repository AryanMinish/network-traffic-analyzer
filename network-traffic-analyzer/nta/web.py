"""
Web dashboard (Flask): upload a .pcap / .pcapng file in the browser and get the
full HTML traffic report back.

    python -m nta dashboard          ->  http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import tempfile

from flask import Flask, Response, request

from . import analyze_file
from .report import html_report

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "lab_traffic.pcap")

UPLOAD_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Network Traffic Analyzer</title>
<style>
body{margin:0;background:#f4f4f1;color:#0b0b0b;font:15px/1.5 "Segoe UI",Roboto,Arial,sans-serif}
header{background:#13212e;color:#fff;padding:22px 32px}header h1{margin:0;font-size:22px}
header p{margin:4px 0 0;color:#b9c3cc;font-size:13px}
main{max-width:760px;margin:40px auto;padding:0 20px}
.card{background:#fcfcfb;border:1px solid #e6e5e0;border-radius:12px;padding:28px}
h2{margin:0 0 6px;font-size:18px}p.sub{margin:0 0 20px;color:#52514e}
.drop{border:2px dashed #b7c4cf;border-radius:10px;padding:28px;text-align:center;background:#f8faf9}
input[type=file]{margin:12px 0}
button,a.btn{background:#2a78d6;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:14px;
cursor:pointer;text-decoration:none;display:inline-block}
a.btn.secondary{background:#fff;color:#2a78d6;border:1px solid #2a78d6;margin-left:8px}
.err{color:#d03b3b;margin-top:12px}ul{color:#52514e;padding-left:18px}
</style></head><body>
<header><h1>Network Traffic Analyzer</h1><p>Computer Networks Mini Project · packet capture &amp; protocol analysis</p></header>
<main><div class="card"><h2>Analyse a capture file</h2>
<p class="sub">Upload a <b>.pcap</b> or <b>.pcapng</b> file saved from Wireshark, tcpdump or <code>nta capture</code>.</p>
<form method="post" action="/analyze" enctype="multipart/form-data">
<div class="drop"><div>Choose a capture file</div><input type="file" name="pcap" accept=".pcap,.pcapng,.cap" required><br>
<button type="submit">Analyse traffic</button><a class="btn secondary" href="/sample">Try the sample capture</a></div>
</form>{error}
<ul><li>Decodes Ethernet, ARP, IPv4/IPv6, ICMP, TCP, UDP, DNS, HTTP, TLS (SNI), DHCP and NTP</li>
<li>Shows protocol mix, top talkers, conversations, ports and traffic over time</li>
<li>Flags port scans, SYN/ICMP floods, ARP spoofing, DNS tunnelling and clear-text logins</li></ul>
</div></main></body></html>"""


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB uploads

    @app.get("/")
    def index():
        return UPLOAD_PAGE.replace("{error}", "")

    @app.get("/sample")
    def sample():
        return Response(html_report(analyze_file(SAMPLE)), mimetype="text/html")

    @app.post("/analyze")
    def analyze():
        f = request.files.get("pcap")
        if not f or not f.filename:
            return UPLOAD_PAGE.replace("{error}", "<p class='err'>Please choose a file.</p>"), 400
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            f.save(path)
            result = analyze_file(path)
            result.source = f.filename
            return Response(html_report(result), mimetype="text/html")
        except Exception as exc:  # show parsing problems to the user instead of a 500 page
            msg = f"<p class='err'>Could not analyse this file: {exc}</p>"
            return UPLOAD_PAGE.replace("{error}", msg), 400
        finally:
            os.remove(path)

    return app
