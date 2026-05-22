from flask import Flask, render_template, send_file
from flask_socketio import SocketIO
import os
import subprocess
import threading
import sys

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

REPORT_FILE = "Information_Gathered.txt"
RECON_SCRIPT = "recon_script.py"

current_process = None
process_lock = threading.Lock()

PROGRESS_TERMS = [
    "Scanned:",
    "Found:",
    "Elapsed",
    "Overall:",
    "Task ",
    "Querying ",
    "Enumerating ",
    "Testing ",
    "Crawling",
    "Sending trigger",
    "Progress",
    "0%",
    "20%",
    "40%",
    "60%",
    "80%",
    "100%",
    "->",
    "Connecting",
    "Running ",
]

IMPORTANT_TERMS = [
    "Target URL",
    "Domain",
    "Resolved IP",
    "All IPs",
    "WHOIS",
    "Registrar",
    "Creation Date",
    "Expiration Date",
    "Updated Date",
    "Name Server",
    "DNS Records",
    "A     →",
    "AAAA  →",
    "MX    →",
    "NS    →",
    "TXT   →",
    "SOA   →",
    "CNAME →",
    "SRV   →",
    "SSL subject",
    "SSL issuer",
    "SSL version",
    "SSL serialNumber",
    "SSL notBefore",
    "SSL notAfter",
    "Final URL",
    "Status Code",
    "Reason",
    "Content-Type",
    "Content-Length",
    "Security Headers",
    "Cookies",
    "WAF DETECTED",
    "LOAD BALANCER DETECTED",
    "BuiltWith",
    "WhatWeb",
    "Technology detected",
    "robots.txt",
    "Sitemap",
    "Pages crawled",
    "Unique URLs discovered",
    "Discovered Directories",
    "Discovered JS",
    "Discovered CSS",
    "Discovered IMAGES",
    "Total forms",
    "Page Title",
    "Meta Tags",
    "Images:",
    "Forms:",
    "Iframes:",
    "HTML comments:",
    "Open Graph Tags",
    "Twitter Card Tags",
    "Interesting Patterns",
    "Email Addresses Found",
]


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/download_report")
def download_report():
    if os.path.exists(REPORT_FILE):
        return send_file(REPORT_FILE, as_attachment=True)
    return "No report found"


def normalize_output(line: str) -> str:
    replacements = {
        "█": "#",
        "░": "-",
        "✓": "[OK]",
        "✗": "[FAIL]",
        "⚠": "[WARN]",
        "►": ">",
        "●": "*",
        "⊕": "+",
        "◐": "*",
        "◓": "*",
        "◑": "*",
        "◒": "*",
        "⠋": "*",
        "⠙": "*",
        "⠹": "*",
        "⠸": "*",
        "⠼": "*",
        "⠴": "*",
        "⠦": "*",
        "⠧": "*",
        "⠇": "*",
        "⠏": "*",
        "▁": "",
        "▂": "",
        "▃": "",
        "▄": "",
        "▅": "",
        "▆": "",
        "▇": "",
    }

    clean = line.replace("\r", "").rstrip("\n")
    for old, new in replacements.items():
        clean = clean.replace(old, new)
    return clean.strip()


def should_include_in_report(clean_line: str) -> bool:
    if not clean_line:
        return False

    lower = clean_line.lower()

    if any(term.lower() in lower for term in PROGRESS_TERMS):
        return False

    if clean_line[0] in "/-\\|":
        return False

    if any(term.lower() in lower for term in IMPORTANT_TERMS):
        return True

    if "→" in clean_line:
        return True

    if clean_line.startswith("[+]"):
        return True

    if clean_line.startswith("OK "):
        return True

    if clean_line.startswith("FAIL "):
        return True

    return False


def run_scan(target):
    global current_process

    try:
        with process_lock:
            if os.path.exists(REPORT_FILE):
                os.remove(REPORT_FILE)

            current_process = subprocess.Popen(
                [sys.executable, "-u", RECON_SCRIPT, target],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="ignore",
                bufsize=1,
            )

        report_lines = []

        while True:
            line = current_process.stdout.readline()

            if not line and current_process.poll() is not None:
                break

            if not line:
                continue

            clean_line = normalize_output(line)

            if clean_line:
                socketio.emit("scan_output", {"data": clean_line})

                if should_include_in_report(clean_line):
                    report_lines.append(clean_line)
                    socketio.emit("report_update", {"data": clean_line})

        if current_process.stdout:
            current_process.stdout.close()

        current_process.wait()

        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))

        socketio.emit("scan_complete", {"data": "Recon Scan Completed"})

    except Exception as e:
        socketio.emit("scan_output", {"data": f"[ERROR] {str(e)}"})


@socketio.on("start_scan")
def start_scan(data):
    target = (data or {}).get("target", "").strip()

    if not target:
        socketio.emit("scan_output", {"data": "[ERROR] No target provided"})
        return

    thread = threading.Thread(target=run_scan, args=(target,), daemon=True)
    thread.start()


@socketio.on("stop_scan")
def stop_scan():
    global current_process

    try:
        with process_lock:
            if current_process and current_process.poll() is None:
                current_process.kill()
                socketio.emit("scan_output", {"data": "[!] Scan stopped by user"})
                socketio.emit("scan_complete", {"data": "Stopped"})
    except Exception as e:
        socketio.emit("scan_output", {"data": f"[ERROR] {str(e)}"})


if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True,
    )