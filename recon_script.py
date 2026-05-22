#!/usr/bin/env python3
"""
=============================================================================
  Comprehensive Web Information Gathering Script
  Performs 15 reconnaissance tasks against a target website.
  Saves all output to 'Information_Gathered.txt' in structured format.
  Features real-time scanning process visualization.
=============================================================================
DISCLAIMER: This script is intended for authorized security testing and
educational purposes ONLY. Unauthorized use against systems you do not own
or have explicit permission to test is illegal and unethical.
=============================================================================
"""
import subprocess
import sys
import os
import time
import threading
import itertools
import io
import shutil
from datetime import datetime
# Make terminal output UTF-8 safe on Windows consoles
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
# ------------------------------------------------------------------------------
# STEP 0 — Install all required dependencies
# ------------------------------------------------------------------------------
REQUIRED_PIP_PACKAGES = [
    "requests",
    "beautifulsoup4",
    "python-whois",
    "dnspython",
    "builtwith",
    "python-nmap",
    "wafw00f",
    "lxml",
    "colorama",
    "tldextract",
    "PyPDF2",
    "Pillow",
]
REQUIRED_SYSTEM_TOOLS = [
    "nmap",
    "curl",
]
OPTIONAL_SYSTEM_TOOLS = [
    "whatweb",
    "wget",
    "gobuster",
    "nikto",
    "dig",
]
def install_pip_packages():
    """Install all required pip packages."""
    print("\n[*] Installing required Python packages...")
    total = len(REQUIRED_PIP_PACKAGES)
    for idx, pkg in enumerate(REQUIRED_PIP_PACKAGES, 1):
        progress = int((idx / total) * 30)
        bar = "#" * progress + "-" * (30 - progress)
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", pkg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"\r    [{bar}] {idx}/{total}  OK {pkg:<25s}", end="", flush=True)
        except subprocess.CalledProcessError:
            print(f"\r    [{bar}] {idx}/{total}  FAIL {pkg:<25s}", end="", flush=True)
    print()
def check_system_tools():
    """Check which system-level tools are required/optional."""
    print("\n[*] Checking system-level tools...")
    available, missing = {}, []
    # Required tools
    total = len(REQUIRED_SYSTEM_TOOLS)
    for idx, tool in enumerate(REQUIRED_SYSTEM_TOOLS, 1):
        progress = int((idx / total) * 30) if total else 30
        bar = "#" * progress + "-" * (30 - progress)
        path = shutil.which(tool) or ""
        if path:
            available[tool] = path
            print(f"\r    [{bar}] {idx}/{total}  OK {tool:<15s} -> {path}", end="", flush=True)
        else:
            missing.append(tool)
            print(f"\r    [{bar}] {idx}/{total}  FAIL {tool:<15s} -> NOT FOUND", end="", flush=True)
        time.sleep(0.1)
    print()
    # Optional tools (Windows may not have them)
    if OPTIONAL_SYSTEM_TOOLS:
        print("\n[*] Optional tools (skipped if missing on Windows)...")
        opt_total = len(OPTIONAL_SYSTEM_TOOLS)
        for idx, tool in enumerate(OPTIONAL_SYSTEM_TOOLS, 1):
            progress = int((idx / opt_total) * 30) if opt_total else 30
            bar = "#" * progress + "-" * (30 - progress)
            path = shutil.which(tool) or ""
            if path:
                available[tool] = path
                print(f"\r    [{bar}] {idx}/{opt_total}  OPTIONAL {tool:<15s} -> {path}", end="", flush=True)
            else:
                print(f"\r    [{bar}] {idx}/{opt_total}  OPTIONAL {tool:<15s} -> skipped on Windows", end="", flush=True)
            time.sleep(0.05)
        print()
    return available, missing
print("\n[OK] Python dependencies should already be installed in the active environment.")
AVAILABLE_TOOLS, MISSING_TOOLS = check_system_tools()
# ------------------------------------------------------------------------------
# Now import everything we installed
# ------------------------------------------------------------------------------
import re
import json
import socket
import ssl
import struct
import http.client
import urllib.parse
from collections import Counter
from io import BytesIO
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup, Comment
from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)
try:
    import whois
except ImportError:
    whois = None
try:
    import dns.resolver
    import dns.zone
    import dns.query
except ImportError:
    dns = None
try:
    import builtwith
except ImportError:
    builtwith = None
try:
    import nmap
except ImportError:
    nmap = None
try:
    import tldextract
except ImportError:
    tldextract = None
# +---------------------------------------------------------------------------+
# |                  LIVE SCANNING DISPLAY ENGINE                            |
# +---------------------------------------------------------------------------+
class ScanProgress:
    """Thread-safe animated spinner + live status for scan operations."""
    SPINNER_CHARS = ["|", "/", "-", "\\"]
    SCAN_ANIM = [".", "o", "O", "@"]
    WAVE = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "#", "▇", "▆", "▅", "▄", "▃", "▂"]
    def __init__(self, task_name=""):
        self._running = False
        self._thread = None
        self._status = ""
        self._detail = ""
        self._task_name = task_name
        self._found_count = 0
        self._scanned_count = 0
        self._total_count = 0
        self._lock = threading.Lock()
        self._start_time = 0
    def start(self, status="Scanning..."):
        """Start the spinner in a background thread."""
        self._running = True
        self._status = status
        self._detail = ""
        self._found_count = 0
        self._scanned_count = 0
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    def update(self, status=None, detail=None, found=None, scanned=None, total=None):
        """Update the live display status from the main thread."""
        with self._lock:
            if status is not None:
                self._status = status
            if detail is not None:
                self._detail = detail
            if found is not None:
                self._found_count = found
            if scanned is not None:
                self._scanned_count = scanned
            if total is not None:
                self._total_count = total
    def stop(self, final_msg="Done"):
        """Stop the spinner and print a final line."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        elapsed = time.time() - self._start_time
        # Clear the line
        print(f"\r{' ' * 120}\r", end="", flush=True)
        print(
            Fore.GREEN
            + f"    OK {final_msg} "
            + Fore.WHITE
            + f"({elapsed:.1f}s)"
        )
    def _spin(self):
        """Background thread: animate spinner + display live status."""
        cycle = itertools.cycle(self.SPINNER_CHARS)
        wave_idx = 0
        while self._running:
            spinner = next(cycle)
            elapsed = time.time() - self._start_time
            wave_segment = "".join(
                self.WAVE[(wave_idx + i) % len(self.WAVE)] for i in range(8)
            )
            wave_idx = (wave_idx + 1) % len(self.WAVE)
            with self._lock:
                status = self._status
                detail = self._detail
                found = self._found_count
                scanned = self._scanned_count
                total = self._total_count
            # Build progress bar if total is known
            progress_bar = ""
            if total > 0:
                pct = min(int((scanned / total) * 100), 100)
                filled = int(pct / 4)
                progress_bar = (
                    f" [{Fore.CYAN}{'#' * filled}{'-' * (25 - filled)}{Fore.YELLOW}]"
                    f" {pct}%"
                )
            # Build counters
            counters = ""
            if scanned > 0 or found > 0:
                counters = f"  Scanned:{Fore.WHITE}{scanned}"
                if found > 0:
                    counters += f"  {Fore.GREEN}Found:{found}"
                counters += Fore.YELLOW
            # Build detail line
            detail_str = f"  {Fore.WHITE}-> {detail}{Fore.YELLOW}" if detail else ""
            line = (
                f"\r    {Fore.YELLOW}{spinner} {wave_segment} "
                f"{Fore.CYAN}{status}"
                f"{progress_bar}{counters}{detail_str}"
                f"  {Fore.WHITE}[{elapsed:.0f}s]"
            )
            # Pad to clear previous line
            print(f"{line:<140s}", end="", flush=True)
            time.sleep(0.1)
class TaskTracker:
    """Tracks and displays overall task progress across the scan."""
    def __init__(self, total_tasks):
        self.total = total_tasks
        self.current = 0
        self.start_time = time.time()
    def begin_task(self, task_num, task_name):
        """Display the task header with overall progress."""
        self.current = task_num
        elapsed = time.time() - self.start_time
        pct = int((task_num - 1) / self.total * 100)
        bar_len = 40
        filled = int(pct / 100 * bar_len)
        bar = "#" * filled + "-" * (bar_len - filled)
        print()
        print(Fore.CYAN + "  +" + "-" * 78 + "+")
        print(
            Fore.CYAN + "  |"
            + Fore.WHITE + Style.BRIGHT
            + f"  Task {task_num}/{self.total}: {task_name}".ljust(77)
            + Fore.CYAN + "|"
        )
        print(
            Fore.CYAN + "  |"
            + Fore.YELLOW
            + f"  Overall: [{bar}] {pct}%  Elapsed: {elapsed:.0f}s".ljust(77)
            + Fore.CYAN + "|"
        )
        print(Fore.CYAN + "  +" + "-" * 78 + "+")
    def complete_task(self, task_name):
        """Mark current task complete."""
        elapsed = time.time() - self.start_time
        print(
            Fore.GREEN + Style.BRIGHT
            + f"  [OK] Task {self.current}/{self.total} complete: {task_name}"
            + Fore.WHITE + f" [Total: {elapsed:.0f}s]"
        )
def live_print(msg, level="info"):
    """Print a live-feed line during scanning."""
    icons = {
        "info":    Fore.CYAN    + "    ℹ ",
        "found":   Fore.GREEN   + "    + ",
        "warn":    Fore.YELLOW  + "    WARN ",
        "error":   Fore.RED     + "    FAIL ",
        "scan":    Fore.MAGENTA + "    > ",
        "result":  Fore.WHITE   + "    * ",
    }
    prefix = icons.get(level, icons["info"])
    print(f"\r{' ' * 140}\r{prefix}{Fore.WHITE}{msg}", flush=True)
# +---------------------------------------------------------------------------+
# |                        UTILITY HELPERS                                   |
# +---------------------------------------------------------------------------+
OUTPUT_FILE = "Information_Gathered.txt"
SECTION_SEP = "=" * 80
SUBSECTION_SEP = "-" * 60
TIMEOUT = 15
results = []  # Collects all output sections
def banner():
    b = r"""
  +--------------------------------------------------------------+
  |        WEB INFORMATION GATHERING FRAMEWORK v3.0             |
  |    Comprehensive Reconnaissance & Footprinting              |
  |          with LIVE Scanning Process Display                 |
  +--------------------------------------------------------------+
    """
    print(Fore.CYAN + Style.BRIGHT + b)
def log_section(title: str, content: str):
    """Store a formatted section for later writing."""
    block = f"\n{SECTION_SEP}\n  {title}\n{SECTION_SEP}\n{content}\n"
    results.append(block)
def run_cmd(cmd: str, timeout: int = 120) -> str:
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] Command timed out."
    except Exception as e:
        return f"[!] Error running command: {e}"
def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url
def extract_domain(url: str) -> str:
    """Extract the hostname from a URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname or parsed.path.split("/")[0]
def safe_request(url, **kwargs):
    """Make a GET request with error handling."""
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("allow_redirects", True)
    kwargs.setdefault(
        "headers",
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        },
    )
    return requests.get(url, **kwargs)
# +---------------------------------------------------------------------------+
# |                1. WEBSITE FOOTPRINTING                                   |
# +---------------------------------------------------------------------------+
def website_footprinting(url: str, domain: str):
    sp = ScanProgress("Footprinting")
    out_lines = []
    # -- IP Resolution --
    sp.start("Resolving target IP address...")
    live_print(f"Resolving DNS for {domain}...", "scan")
    try:
        ip = socket.gethostbyname(domain)
        out_lines.append(f"  Target URL       : {url}")
        out_lines.append(f"  Domain           : {domain}")
        out_lines.append(f"  Resolved IP      : {ip}")
        live_print(f"IP resolved: {ip}", "found")
    except socket.gaierror as e:
        ip = "N/A"
        out_lines.append(f"  [!] DNS resolution failed: {e}")
        live_print(f"DNS resolution failed: {e}", "error")
    sp.stop(f"IP Resolution -> {ip}")
    # -- All IPs --
    sp.start("Gathering all IP addresses...")
    try:
        all_ips = socket.getaddrinfo(domain, None)
        unique = set(addr[4][0] for addr in all_ips)
        out_lines.append(f"  All IPs          : {', '.join(unique)}")
        for uip in unique:
            live_print(f"Additional IP: {uip}", "found")
    except Exception:
        pass
    sp.stop(f"All IPs gathered")
    # -- WHOIS --
    sp.start("Performing WHOIS lookup...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  WHOIS Information:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if whois:
        try:
            live_print(f"Querying WHOIS server for {domain}...", "scan")
            w = whois.whois(domain)
            for key in [
                "domain_name", "registrar", "whois_server", "creation_date",
                "expiration_date", "updated_date", "name_servers", "status",
                "emails", "org", "address", "city", "state", "country",
            ]:
                val = getattr(w, key, None)
                if val:
                    out_lines.append(f"    {key:20s}: {val}")
                    live_print(f"WHOIS {key}: {str(val)[:60]}", "result")
            sp.stop("WHOIS lookup complete")
        except Exception as e:
            out_lines.append(f"    [!] WHOIS lookup error: {e}")
            sp.stop(f"WHOIS error: {e}")
    else:
        out_lines.append("    [!] python-whois not available")
        sp.stop("python-whois not available")
    # -- DNS Records --
    sp.start("Enumerating DNS records...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  DNS Records:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    dns_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]
    if dns:
        found_records = 0
        for i, rtype in enumerate(dns_types):
            sp.update(
                detail=f"Querying {rtype} records...",
                scanned=i + 1,
                total=len(dns_types),
            )
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for rdata in answers:
                    out_lines.append(f"    {rtype:6s} -> {rdata}")
                    found_records += 1
                    live_print(f"DNS {rtype}: {rdata}", "found")
                    sp.update(found=found_records)
            except Exception:
                pass
        # Reverse DNS
        if ip != "N/A":
            try:
                rev = socket.gethostbyaddr(ip)
                out_lines.append(f"    rDNS   -> {rev[0]}")
                live_print(f"rDNS: {rev[0]}", "found")
            except Exception:
                pass
        sp.stop(f"DNS enumeration complete — {found_records} records found")
    else:
        out_lines.append("    [!] dnspython not available")
        sp.stop("dnspython not available")
    # -- SSL/TLS Certificate --
    sp.start("Extracting SSL/TLS certificate...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  SSL/TLS Certificate:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        live_print(f"Connecting to {domain}:443 for SSL cert...", "scan")
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(TIMEOUT)
            s.connect((domain, 443))
            cert = s.getpeercert()
            for k, v in cert.items():
                out_lines.append(f"    {k}: {v}")
                live_print(f"SSL {k}: {str(v)[:70]}", "result")
        sp.stop("SSL certificate extracted")
    except Exception as e:
        out_lines.append(f"    [!] SSL info error: {e}")
        sp.stop(f"SSL extraction failed")
    # -- Geo-location --
    sp.start("Looking up IP geolocation...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  IP Geolocation:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if ip != "N/A":
        try:
            live_print(f"Querying ip-api.com for {ip}...", "scan")
            geo = requests.get(
                f"http://ip-api.com/json/{ip}", timeout=TIMEOUT
            ).json()
            for k in [
                "country", "regionName", "city", "zip", "lat", "lon",
                "timezone", "isp", "org", "as",
            ]:
                out_lines.append(f"    {k:14s}: {geo.get(k, 'N/A')}")
                live_print(f"Geo {k}: {geo.get(k, 'N/A')}", "result")
            sp.stop(f"Geolocation: {geo.get('city','?')}, {geo.get('country','?')}")
        except Exception as e:
            out_lines.append(f"    [!] Geolocation error: {e}")
            sp.stop("Geolocation failed")
    else:
        sp.stop("Skipped — no IP available")
    log_section("1. WEBSITE FOOTPRINTING", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |                2. WEBSITE ENUMERATION                                    |
# +---------------------------------------------------------------------------+
def website_enumeration(url: str, domain: str):
    sp = ScanProgress("Enumeration")
    out_lines = []
    # -- Subdomains via crt.sh --
    sp.start("Querying crt.sh for subdomains...")
    out_lines.append("  Subdomain Enumeration (crt.sh):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        live_print(f"Fetching certificate transparency logs for {domain}...", "scan")
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json", timeout=20
        )
        if r.status_code == 200:
            entries = r.json()
            subdomains = sorted(
                set(
                    entry["name_value"].strip()
                    for entry in entries
                    if "name_value" in entry
                )
            )
            for idx, sd in enumerate(subdomains[:100]):
                out_lines.append(f"    {sd}")
                if idx < 15:
                    live_print(f"Subdomain: {sd}", "found")
                sp.update(found=idx + 1, detail=sd)
            out_lines.append(f"    Total unique subdomains found: {len(subdomains)}")
            sp.stop(f"crt.sh — {len(subdomains)} subdomains found")
        else:
            out_lines.append(f"    [!] crt.sh returned status {r.status_code}")
            sp.stop(f"crt.sh returned {r.status_code}")
    except Exception as e:
        out_lines.append(f"    [!] Subdomain enum error: {e}")
        sp.stop(f"crt.sh error")
    # -- Common subdomains brute-force --
    sp.start("Brute-forcing common subdomains...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Common Subdomain Brute-Force:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    common_subs = [
        "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "test", "dev", "staging", "api", "m", "mobile", "blog", "shop",
        "store", "portal", "vpn", "remote", "secure", "login", "dashboard",
        "app", "beta", "demo", "status", "docs", "support", "help", "cdn",
        "static", "media", "img", "images", "assets", "db", "database",
        "git", "svn", "jenkins", "ci", "build", "deploy", "monitoring",
        "grafana", "kibana", "elastic", "prometheus", "nagios", "zabbix",
    ]
    alive_subs = []
    total_subs = len(common_subs)
    for idx, sub in enumerate(common_subs):
        fqdn = f"{sub}.{domain}"
        sp.update(
            detail=f"Testing {fqdn}",
            scanned=idx + 1,
            total=total_subs,
            found=len(alive_subs),
        )
        try:
            socket.gethostbyname(fqdn)
            alive_subs.append(fqdn)
            out_lines.append(f"    [ALIVE] {fqdn}")
            live_print(f"Subdomain alive: {fqdn}", "found")
        except socket.gaierror:
            pass
    out_lines.append(f"    Total alive: {len(alive_subs)}")
    sp.stop(f"Subdomain brute-force — {len(alive_subs)} alive out of {total_subs}")
    # -- Email harvesting --
    sp.start("Harvesting email addresses from page...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Email Addresses Found:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        resp = safe_request(url)
        emails = set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", resp.text))
        for e in emails:
            out_lines.append(f"    {e}")
            live_print(f"Email found: {e}", "found")
        if not emails:
            out_lines.append("    No emails found on the main page.")
        sp.stop(f"Email harvest — {len(emails)} found")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("Email harvest failed")
    # -- robots.txt --
    sp.start("Fetching robots.txt...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  robots.txt:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        r = safe_request(urllib.parse.urljoin(url, "/robots.txt"))
        if r.status_code == 200 and "user-agent" in r.text.lower():
            out_lines.append(r.text[:3000])
            live_print("robots.txt found and retrieved", "found")
            sp.stop("robots.txt retrieved")
        else:
            out_lines.append("    robots.txt not found or empty.")
            sp.stop("robots.txt not found")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("robots.txt fetch error")
    log_section("2. WEBSITE ENUMERATION", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |                3. ANALYZE HTML SOURCE CODE                               |
# +---------------------------------------------------------------------------+
def analyze_html_source(url: str):
    sp = ScanProgress("HTML Analysis")
    out_lines = []
    sp.start("Downloading and parsing HTML source...")
    try:
        resp = safe_request(url)
        soup = BeautifulSoup(resp.text, "lxml")
        html = resp.text
        live_print(f"Page downloaded: {len(html)} bytes", "info")
        # Title
        sp.update(detail="Extracting page title...")
        title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
        out_lines.append(f"  Page Title       : {title}")
        live_print(f"Title: {title}", "result")
        # Meta tags
        sp.update(detail="Parsing meta tags...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Meta Tags:")
        meta_tags = soup.find_all("meta")
        for meta in meta_tags:
            attrs = dict(meta.attrs)
            out_lines.append(f"    {attrs}")
        live_print(f"Meta tags: {len(meta_tags)} found", "found")
        # Links
        sp.update(detail="Analyzing hyperlinks...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Hyperlinks:")
        internal, external = [], []
        parsed_base = urllib.parse.urlparse(url)
        all_links = soup.find_all("a", href=True)
        for i, a in enumerate(all_links):
            sp.update(scanned=i + 1, total=len(all_links))
            href = a["href"]
            full = urllib.parse.urljoin(url, href)
            parsed = urllib.parse.urlparse(full)
            if parsed.hostname and parsed.hostname != parsed_base.hostname:
                external.append(full)
            else:
                internal.append(full)
        out_lines.append(f"    Internal links : {len(internal)}")
        for l in internal[:30]:
            out_lines.append(f"      {l}")
        out_lines.append(f"    External links : {len(external)}")
        for l in external[:30]:
            out_lines.append(f"      {l}")
        live_print(f"Links: {len(internal)} internal, {len(external)} external", "found")
        # Scripts
        sp.update(detail="Extracting JavaScript files...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  JavaScript Files:")
        scripts = soup.find_all("script", src=True)
        for s in scripts:
            out_lines.append(f"    {urllib.parse.urljoin(url, s['src'])}")
        out_lines.append(f"    Total: {len(scripts)}")
        inline_scripts = soup.find_all("script", src=False)
        out_lines.append(f"    Inline script blocks: {len(inline_scripts)}")
        live_print(f"Scripts: {len(scripts)} external, {len(inline_scripts)} inline", "found")
        # Stylesheets
        sp.update(detail="Extracting CSS stylesheets...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  CSS Stylesheets:")
        css = soup.find_all("link", rel="stylesheet")
        for c in css:
            href = c.get("href", "N/A")
            out_lines.append(f"    {urllib.parse.urljoin(url, href)}")
        out_lines.append(f"    Total: {len(css)}")
        live_print(f"Stylesheets: {len(css)} found", "found")
        # Images
        sp.update(detail="Extracting images...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Images:")
        imgs = soup.find_all("img")
        for img in imgs[:30]:
            src = img.get("src", "N/A")
            alt = img.get("alt", "")
            out_lines.append(f"    src={urllib.parse.urljoin(url, src)}  alt=\"{alt}\"")
        out_lines.append(f"    Total: {len(imgs)}")
        live_print(f"Images: {len(imgs)} found", "found")
        # Forms
        sp.update(detail="Analyzing forms...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Forms:")
        forms = soup.find_all("form")
        for i, form in enumerate(forms):
            out_lines.append(f"    Form #{i+1}:")
            out_lines.append(f"      Action : {form.get('action', 'N/A')}")
            out_lines.append(f"      Method : {form.get('method', 'GET')}")
            inputs = form.find_all("input")
            for inp in inputs:
                out_lines.append(
                    f"      Input  : name={inp.get('name','N/A')} "
                    f"type={inp.get('type','text')} "
                    f"value={inp.get('value','')}"
                )
            live_print(f"Form #{i+1}: action={form.get('action','N/A')} method={form.get('method','GET')}", "found")
        out_lines.append(f"    Total forms: {len(forms)}")
        # iframes
        sp.update(detail="Extracting iframes...")
        iframes = soup.find_all("iframe")
        if iframes:
            out_lines.append(f"\n  {SUBSECTION_SEP}")
            out_lines.append("  Iframes:")
            for iframe in iframes:
                out_lines.append(f"    src={iframe.get('src', 'N/A')}")
                live_print(f"Iframe: {iframe.get('src', 'N/A')}", "found")
        # HTML Comments
        sp.update(detail="Searching HTML comments...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  HTML Comments:")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for c in comments[:20]:
            out_lines.append(f"    <!-- {c.strip()[:200]} -->")
        out_lines.append(f"    Total comments: {len(comments)}")
        live_print(f"HTML comments: {len(comments)} found", "found")
        # Page size
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append(f"  HTML Size        : {len(html)} bytes")
        out_lines.append(f"  Total Tags       : {len(soup.find_all())}")
        sp.stop(
            f"HTML analysis complete — {len(soup.find_all())} tags, "
            f"{len(internal)+len(external)} links, {len(forms)} forms"
        )
    except Exception as e:
        out_lines.append(f"  [!] Error analyzing HTML: {e}")
        sp.stop(f"HTML analysis error")
    log_section("3. HTML SOURCE CODE ANALYSIS", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          4. HTTP/HTML PROCESSING BY THE BROWSER                          |
# +---------------------------------------------------------------------------+
def check_http_processing(url: str):
    sp = ScanProgress("HTTP Processing")
    out_lines = []
    sp.start("Analyzing HTTP response...")
    try:
        resp = safe_request(url)
        sp.update(detail="Parsing response overview...")
        out_lines.append("  Response Overview:")
        out_lines.append(f"    Final URL       : {resp.url}")
        out_lines.append(f"    Status Code     : {resp.status_code}")
        out_lines.append(f"    Reason          : {resp.reason}")
        out_lines.append(f"    Encoding        : {resp.encoding}")
        out_lines.append(f"    Apparent Enc.   : {resp.apparent_encoding}")
        out_lines.append(f"    Content-Type    : {resp.headers.get('Content-Type', 'N/A')}")
        out_lines.append(f"    Content-Length  : {resp.headers.get('Content-Length', 'N/A')}")
        out_lines.append(f"    Elapsed Time    : {resp.elapsed}")
        live_print(f"Status: {resp.status_code} {resp.reason}", "result")
        # Redirect chain
        sp.update(detail="Tracing redirect chain...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Redirect Chain:")
        if resp.history:
            for i, r in enumerate(resp.history):
                loc = r.headers.get('Location', 'N/A')
                out_lines.append(f"    [{i+1}] {r.status_code} -> {loc}")
                live_print(f"Redirect: {r.status_code} -> {loc}", "found")
        else:
            out_lines.append("    No redirects.")
        sp.stop("Response analysis complete")
        # All response headers
        sp.start("Enumerating response headers...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Response Headers:")
        for k, v in resp.headers.items():
            out_lines.append(f"    {k}: {v}")
        live_print(f"Response headers: {len(resp.headers)} found", "info")
        sp.stop(f"{len(resp.headers)} headers enumerated")
        # Security headers check
        sp.start("Auditing security headers...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Security Headers Audit:")
        sec_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
            "Feature-Policy": "Feature-Policy",
            "X-Permitted-Cross-Domain-Policies": "X-Permitted-Cross-Domain-Policies",
            "Expect-CT": "Expect-CT",
            "Cross-Origin-Opener-Policy": "COOP",
            "Cross-Origin-Resource-Policy": "CORP",
            "Cross-Origin-Embedder-Policy": "COEP",
        }
        present_count = 0
        missing_count = 0
        for header, label in sec_headers.items():
            sp.update(detail=f"Checking {label}...")
            val = resp.headers.get(header)
            status = f"Present -> {val}" if val else "MISSING"
            marker = "[+]" if val else "[-]"
            out_lines.append(f"    {marker} {label:40s}: {status}")
            if val:
                present_count += 1
                live_print(f"Security header present: {label}", "found")
            else:
                missing_count += 1
        sp.stop(f"Security audit — {present_count} present, {missing_count} missing")
        # Cookies
        sp.start("Analyzing cookies...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Cookies:")
        if resp.cookies:
            for cookie in resp.cookies:
                out_lines.append(f"    Name    : {cookie.name}")
                out_lines.append(f"    Value   : {cookie.value[:80]}")
                out_lines.append(f"    Domain  : {cookie.domain}")
                out_lines.append(f"    Path    : {cookie.path}")
                out_lines.append(f"    Secure  : {cookie.secure}")
                out_lines.append(f"    HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")
                out_lines.append("")
                live_print(f"Cookie: {cookie.name}={cookie.value[:40]}...", "found")
            sp.stop(f"{len(resp.cookies)} cookies analyzed")
        else:
            out_lines.append("    No cookies set.")
            sp.stop("No cookies found")
        # HTTP Methods
        sp.start("Testing HTTP methods...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  HTTP Methods Test:")
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
        allowed = []
        for idx, method in enumerate(methods):
            sp.update(detail=f"Testing {method}...", scanned=idx + 1, total=len(methods))
            try:
                r = requests.request(
                    method, url, timeout=TIMEOUT, verify=False, allow_redirects=False
                )
                out_lines.append(f"    {method:8s} -> {r.status_code}")
                if r.status_code < 405:
                    allowed.append(method)
                    live_print(f"HTTP {method}: {r.status_code} (allowed)", "found")
            except Exception:
                out_lines.append(f"    {method:8s} -> Error")
        sp.stop(f"HTTP methods — {len(allowed)} allowed: {', '.join(allowed)}")
    except Exception as e:
        out_lines.append(f"  [!] Error: {e}")
        sp.stop("HTTP processing failed")
    log_section("4. HTTP/HTML PROCESSING CHECK", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          5. IDENTIFY SERVER-SIDE TECHNOLOGIES                            |
# +---------------------------------------------------------------------------+
def identify_server_technologies(url: str, domain: str):
    sp = ScanProgress("Technology Detection")
    out_lines = []
    # -- HTTP Headers analysis --
    sp.start("Fingerprinting via HTTP headers...")
    out_lines.append("  Technology Hints from HTTP Headers:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        resp = safe_request(url)
        tech_headers = [
            "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
            "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
            "X-Cache", "X-Runtime", "X-Request-Id",
        ]
        for h in tech_headers:
            val = resp.headers.get(h)
            if val:
                out_lines.append(f"    {h}: {val}")
                live_print(f"Header tech: {h} = {val}", "found")
        cookies_str = resp.headers.get("Set-Cookie", "")
        cookie_techs = {
            "PHPSESSID": "PHP",
            "JSESSIONID": "Java/J2EE",
            "ASP.NET": "ASP.NET",
            "laravel_session": "Laravel (PHP)",
            "rack.session": "Ruby/Rack",
            "csrftoken": "Django (Python)",
        }
        for marker, tech in cookie_techs.items():
            if marker in cookies_str:
                out_lines.append(f"    [i] {tech} detected ({marker} cookie)")
                live_print(f"Cookie tech: {tech} detected", "found")
        sp.stop("HTTP header fingerprinting complete")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("Header fingerprinting failed")
    # -- BuiltWith --
    sp.start("Running BuiltWith analysis...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  BuiltWith Analysis:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if builtwith:
        try:
            techs = builtwith.parse(url)
            for category, items in techs.items():
                out_lines.append(f"    {category}:")
                for item in items:
                    out_lines.append(f"      - {item}")
                    live_print(f"BuiltWith: {category} -> {item}", "found")
            sp.stop(f"BuiltWith — {sum(len(v) for v in techs.values())} technologies")
        except Exception as e:
            out_lines.append(f"    [!] BuiltWith error: {e}")
            sp.stop("BuiltWith failed")
    else:
        out_lines.append("    [!] builtwith module not available")
        sp.stop("builtwith not available")
    # -- WhatWeb --
    sp.start("Running WhatWeb scanner...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  WhatWeb Analysis:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if "whatweb" in AVAILABLE_TOOLS:
        live_print("Executing whatweb (aggressive mode)...", "scan")
        result = run_cmd(f"whatweb -a 3 --color=never {url} 2>/dev/null", timeout=60)
        out_lines.append(f"    {result.strip()}")
        sp.stop("WhatWeb scan complete")
    else:
        out_lines.append("    [!] whatweb skipped on Windows (optional)")
        sp.stop("whatweb skipped on Windows (optional)")
    # -- HTML-Based Technology Detection --
    sp.start("Scanning HTML for technology signatures...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  HTML-Based Technology Detection:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        resp = safe_request(url)
        html = resp.text.lower()
        tech_sigs = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Joomla": ["joomla", "/components/com_", "/media/jui/"],
            "Drupal": ["drupal", "sites/default/files", "sites/all/"],
            "Magento": ["magento", "mage/", "skin/frontend/"],
            "Shopify": ["shopify", "cdn.shopify.com"],
            "Wix": ["wix.com", "parastorage.com"],
            "Squarespace": ["squarespace.com", "sqsp.net"],
            "React": ["react", "reactdom", "_next/"],
            "Angular": ["ng-version", "angular", "ng-app"],
            "Vue.js": ["vue.js", "vuejs", "__vue__"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Tailwind CSS": ["tailwindcss", "tailwind"],
            "Next.js": ["_next/static", "__next", "nextjs"],
            "Nuxt.js": ["nuxt", "__nuxt"],
            "Laravel": ["laravel"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["flask"],
            "Express": ["express"],
            "Ruby on Rails": ["rails", "ruby"],
            "Google Analytics": ["google-analytics.com", "gtag(", "ga.js"],
            "Google Tag Manager": ["googletagmanager.com", "gtm.js"],
            "Cloudflare": ["cloudflare", "cf-ray"],
            "AWS": ["amazonaws.com"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "IIS": ["iis", "aspnet"],
        }
        detected_techs = 0
        total_sigs = len(tech_sigs)
        for idx, (tech, signatures) in enumerate(tech_sigs.items()):
            sp.update(
                detail=f"Checking {tech}...",
                scanned=idx + 1,
                total=total_sigs,
                found=detected_techs,
            )
            for sig in signatures:
                if sig in html:
                    out_lines.append(f"    [+] {tech} (signature: '{sig}')")
                    live_print(f"Technology detected: {tech}", "found")
                    detected_techs += 1
                    break
        sp.stop(f"HTML signature scan — {detected_techs} technologies detected")
    except Exception:
        sp.stop("HTML signature scan failed")
    log_section("5. SERVER-SIDE TECHNOLOGIES", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          6. MIRROR & CRAWL WEBSITE                                       |
# +---------------------------------------------------------------------------+
def mirror_and_crawl(url: str, domain: str):
    sp = ScanProgress("Crawling")
    out_lines = []
    sp.start("Crawling website (depth=2, max 50 pages)...")
    out_lines.append("  Discovered URLs (Crawl depth=2):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    visited = set()
    to_visit = [url]
    discovered_files = {"js": [], "css": [], "images": [], "documents": [], "other": []}
    directories = set()
    max_pages = 50
    file_extensions = {
        "js": [".js"],
        "css": [".css"],
        "images": [".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp"],
        "documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".csv",
                      ".txt", ".xml", ".json", ".zip", ".rar", ".tar", ".gz"],
    }
    pages_crawled = 0
    total_urls_found = 0
    while to_visit and pages_crawled < max_pages:
        current = to_visit.pop(0)
        if current in visited:
            continue
        visited.add(current)
        pages_crawled += 1
        sp.update(
            detail=f"Page: {current[:60]}...",
            scanned=pages_crawled,
            total=max_pages,
            found=total_urls_found,
        )
        live_print(f"Crawling [{pages_crawled}/{max_pages}]: {current[:80]}", "scan")
        try:
            resp = safe_request(current, timeout=10)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(resp.text, "lxml")
            for tag in soup.find_all(["a", "script", "link", "img", "source", "video", "audio"]):
                href = tag.get("href") or tag.get("src") or ""
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                full_url = urllib.parse.urljoin(current, href)
                parsed = urllib.parse.urlparse(full_url)
                path_parts = parsed.path.rstrip("/").split("/")
                for i in range(1, len(path_parts)):
                    directories.add("/".join(path_parts[:i]) + "/")
                ext = os.path.splitext(parsed.path)[1].lower()
                categorized = False
                for cat, exts in file_extensions.items():
                    if ext in exts:
                        if full_url not in discovered_files[cat]:
                            discovered_files[cat].append(full_url)
                            total_urls_found += 1
                        categorized = True
                        break
                if not categorized and ext and ext != "/":
                    if full_url not in discovered_files["other"]:
                        discovered_files["other"].append(full_url)
                        total_urls_found += 1
                if parsed.hostname == urllib.parse.urlparse(url).hostname:
                    if full_url not in visited:
                        to_visit.append(full_url)
        except Exception:
            continue
    out_lines.append(f"    Pages crawled: {pages_crawled}")
    out_lines.append(f"    Unique URLs discovered: {len(visited)}")
    for page_url in sorted(visited):
        out_lines.append(f"      {page_url}")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Discovered Directories:")
    for d in sorted(directories):
        out_lines.append(f"    {d}")
    for cat, files in discovered_files.items():
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append(f"  Discovered {cat.upper()} files ({len(files)}):")
        for f in files[:50]:
            out_lines.append(f"    {f}")
    sp.stop(
        f"Crawl complete — {pages_crawled} pages, "
        f"{len(directories)} dirs, {total_urls_found} resources"
    )
    # -- wget mirror --
    sp.start("Running wget mirror...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  wget Mirror (directory listing):")
    if "wget" in AVAILABLE_TOOLS:
        mirror_dir = f"/tmp/mirror_{domain}"
        live_print(f"Mirroring to {mirror_dir}...", "scan")
        cmd = (
            f"wget --mirror --convert-links --adjust-extension --page-requisites "
            f"--no-parent -P {mirror_dir} --timeout=10 -t 1 -q "
            f"--reject='*.exe,*.zip,*.tar*,*.gz,*.rar' "
            f"-e robots=off {url} 2>&1 | head -50"
        )
        run_cmd(cmd, timeout=60)
        if os.path.exists(mirror_dir):
            listing = run_cmd(f"find {mirror_dir} -type f | head -100")
            out_lines.append(listing)
            file_count = listing.strip().count("\n") + 1 if listing.strip() else 0
            run_cmd(f"rm -rf {mirror_dir}")
            sp.stop(f"wget mirror complete — {file_count} files")
        else:
            out_lines.append("    Mirror directory not created (site may block wget).")
            sp.stop("wget mirror — site blocked or empty")
    else:
        out_lines.append("    [!] wget skipped on Windows (optional)")
        sp.stop("wget skipped on Windows (optional)")
    log_section("6. MIRROR & CRAWL — FILES, DIRECTORIES, FOLDERS", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          7. IDENTIFY SITEMAP                                             |
# +---------------------------------------------------------------------------+
def identify_sitemap(url: str):
    sp = ScanProgress("Sitemap")
    out_lines = []
    sitemap_paths = [
        "/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml",
        "/sitemap.xml.gz", "/sitemaps.xml", "/sitemap/", "/sitemap.txt",
        "/wp-sitemap.xml", "/post-sitemap.xml", "/page-sitemap.xml",
        "/category-sitemap.xml", "/news-sitemap.xml", "/video-sitemap.xml",
        "/image-sitemap.xml",
    ]
    sp.start("Probing for sitemap files...")
    found_any = False
    total_paths = len(sitemap_paths)
    for idx, path in enumerate(sitemap_paths):
        sitemap_url = urllib.parse.urljoin(url, path)
        sp.update(
            detail=f"Checking {path}",
            scanned=idx + 1,
            total=total_paths,
            found=1 if found_any else 0,
        )
        try:
            r = safe_request(sitemap_url)
            if r.status_code == 200 and len(r.text) > 50:
                found_any = True
                out_lines.append(f"  [+] FOUND: {sitemap_url} ({len(r.text)} bytes)")
                out_lines.append(f"  {SUBSECTION_SEP}")
                live_print(f"Sitemap found: {sitemap_url} ({len(r.text)} bytes)", "found")
                if "xml" in r.headers.get("Content-Type", "") or "<" in r.text[:10]:
                    try:
                        soup = BeautifulSoup(r.text, "lxml")
                        urls = soup.find_all("loc")
                        out_lines.append(f"    URLs in sitemap: {len(urls)}")
                        for u in urls[:50]:
                            out_lines.append(f"      {u.text}")
                        if len(urls) > 50:
                            out_lines.append(f"      ... and {len(urls)-50} more")
                        sitemaps = soup.find_all("sitemap")
                        if sitemaps:
                            out_lines.append(f"\n    Nested sitemaps: {len(sitemaps)}")
                            for sm in sitemaps:
                                loc = sm.find("loc")
                                if loc:
                                    out_lines.append(f"      {loc.text}")
                    except Exception:
                        out_lines.append(r.text[:2000])
                else:
                    out_lines.append(r.text[:2000])
                out_lines.append("")
        except Exception:
            pass
    # robots.txt sitemap
    sp.update(detail="Checking robots.txt for sitemap directives...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Sitemap entries in robots.txt:")
    try:
        r = safe_request(urllib.parse.urljoin(url, "/robots.txt"))
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line.lower().startswith("sitemap:"):
                    out_lines.append(f"    {line}")
                    live_print(f"Sitemap in robots.txt: {line}", "found")
                    found_any = True
    except Exception:
        pass
    if not found_any:
        out_lines.append("  [!] No sitemap found.")
    sp.stop(f"Sitemap scan — {'found' if found_any else 'not found'}")
    log_section("7. SITEMAP IDENTIFICATION", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          8. EXTRACT COMMON WORD LIST                                     |
# +---------------------------------------------------------------------------+
def extract_wordlist(url: str):
    sp = ScanProgress("Wordlist")
    out_lines = []
    sp.start("Extracting and analyzing words from page content...")
    try:
        live_print("Downloading page content...", "scan")
        resp = safe_request(url)
        soup = BeautifulSoup(resp.text, "lxml")
        sp.update(detail="Removing script/style elements...")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
        sp.update(detail="Tokenizing text...")
        words = re.findall(r"[a-zA-Z]{3,}", text)
        words_lower = [w.lower() for w in words]
        live_print(f"Extracted {len(words)} raw words", "info")
        stop_words = {
            "the", "and", "for", "are", "but", "not", "you", "all", "can",
            "her", "was", "one", "our", "out", "has", "have", "had", "this",
            "that", "with", "from", "they", "been", "said", "each", "which",
            "their", "will", "other", "about", "many", "then", "them", "these",
            "some", "would", "make", "like", "into", "than", "its", "over",
            "such", "after", "also", "did", "more", "most", "what", "when",
            "where", "who", "how", "why", "does", "just", "very", "being",
        }
        sp.update(detail="Filtering stop words and counting frequencies...")
        filtered = [w for w in words_lower if w not in stop_words]
        word_freq = Counter(filtered)
        top_words = word_freq.most_common(100)
        out_lines.append(f"  Total words extracted: {len(words)}")
        out_lines.append(f"  Unique words (after filtering): {len(word_freq)}")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Top 100 Most Common Words:")
        out_lines.append(f"  {'Rank':<6} {'Word':<25} {'Count':<8}")
        out_lines.append(f"  {'-'*40}")
        for i, (word, count) in enumerate(top_words, 1):
            out_lines.append(f"  {i:<6} {word:<25} {count:<8}")
            if i <= 10:
                live_print(f"Top word #{i}: '{word}' (×{count})", "result")
        wordlist_file = "extracted_wordlist.txt"
        with open(wordlist_file, "w") as f:
            for word, count in top_words:
                f.write(f"{word}\n")
        out_lines.append(f"\n  [i] Wordlist saved to '{wordlist_file}'")
        sp.stop(
            f"Wordlist extraction — {len(words)} words, "
            f"{len(word_freq)} unique, saved to {wordlist_file}"
        )
    except Exception as e:
        out_lines.append(f"  [!] Error extracting wordlist: {e}")
        sp.stop("Wordlist extraction failed")
    log_section("8. COMMON WORD LIST EXTRACTION", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          9. EXTRACT METADATA AND HIDDEN INFORMATION                      |
# +---------------------------------------------------------------------------+
def extract_metadata(url: str, domain: str):
    sp = ScanProgress("Metadata Extraction")
    out_lines = []
    sp.start("Extracting metadata and hidden information...")
    try:
        resp = safe_request(url)
        soup = BeautifulSoup(resp.text, "lxml")
        # Meta tags
        sp.update(detail="Extracting all meta tags...")
        out_lines.append("  All Meta Tags:")
        out_lines.append(f"  {SUBSECTION_SEP}")
        meta_count = 0
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or meta.get("http-equiv", "")
            content = meta.get("content", "")
            out_lines.append(f"    {name}: {content}")
            meta_count += 1
        live_print(f"Meta tags: {meta_count} extracted", "found")
        # Open Graph
        sp.update(detail="Extracting Open Graph tags...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Open Graph Tags:")
        og_count = 0
        for meta in soup.find_all("meta", attrs={"property": True}):
            prop = meta.get("property", "")
            if prop.startswith("og:"):
                content = meta.get("content", "")
                out_lines.append(f"    {prop}: {content}")
                live_print(f"OG: {prop} = {content[:50]}", "found")
                og_count += 1
        # Twitter Cards
        sp.update(detail="Extracting Twitter Card tags...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Twitter Card Tags:")
        for meta in soup.find_all("meta", attrs={"name": True}):
            name = meta.get("name", "")
            if name.startswith("twitter:"):
                out_lines.append(f"    {name}: {meta.get('content', '')}")
                live_print(f"Twitter: {name}", "found")
        # HTML Comments
        sp.update(detail="Searching for HTML comments...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  HTML Comments (potential hidden info):")
        comments = soup.find_all(string=lambda t: isinstance(t, Comment))
        for c in comments:
            stripped = c.strip()
            if stripped:
                out_lines.append(f"    <!-- {stripped[:300]} -->")
        out_lines.append(f"    Total: {len(comments)} comments")
        live_print(f"HTML comments: {len(comments)} found", "found")
        # Hidden form fields
        sp.update(detail="Scanning hidden form fields...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Hidden Form Fields:")
        hidden_inputs = soup.find_all("input", {"type": "hidden"})
        for h in hidden_inputs:
            out_lines.append(
                f"    name={h.get('name','N/A')} value={h.get('value','')[:100]}"
            )
            live_print(f"Hidden field: {h.get('name','?')}={h.get('value','')[:30]}", "found")
        out_lines.append(f"    Total: {len(hidden_inputs)}")
        # Pattern matching
        sp.update(detail="Scanning for sensitive patterns...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Interesting Patterns in Source:")
        html_text = resp.text
        patterns = {
            "API Keys": r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})',
            "AWS Keys": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "Private Keys": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            "Passwords": r'(?:password|passwd|pwd)["\s:=]+["\']([^"\']{3,})',
            "Email Addresses": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            "IP Addresses": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "Internal Paths": r'(?:/var/www|/home/|/usr/|C:\\|/etc/)',
            "SQL Queries": r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.{5,}(?:FROM|INTO|SET)',
            "Version Numbers": r'(?:version|ver|v)[:\s=]+[\d.]+',
            "TODO/FIXME": r'(?:TODO|FIXME|HACK|BUG|XXX)[\s:].{5,}',
        }
        total_patterns = len(patterns)
        total_findings = 0
        for idx, (name, pattern) in enumerate(patterns.items()):
            sp.update(
                detail=f"Pattern: {name}",
                scanned=idx + 1,
                total=total_patterns,
                found=total_findings,
            )
            matches = re.findall(pattern, html_text, re.IGNORECASE)
            if matches:
                out_lines.append(f"    [{name}] ({len(matches)} found):")
                for m in set(matches[:10]):
                    out_lines.append(f"      {str(m)[:200]}")
                live_print(f"Pattern match: {name} — {len(matches)} hits!", "warn")
                total_findings += len(matches)
        # Generator
        sp.update(detail="Checking generator meta tag...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Generator / CMS Metadata:")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen:
            out_lines.append(f"    Generator: {gen.get('content', 'N/A')}")
            live_print(f"Generator: {gen.get('content', 'N/A')}", "found")
        else:
            out_lines.append("    No generator meta tag found.")
        # HTTP Header metadata
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  HTTP Header Metadata:")
        interesting_headers = [
            "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
            "X-Pingback", "Link", "X-Request-Id", "X-Runtime",
        ]
        for h in interesting_headers:
            val = resp.headers.get(h)
            if val:
                out_lines.append(f"    {h}: {val}")
        sp.stop(f"Metadata extraction — {meta_count} meta, {total_findings} patterns found")
    except Exception as e:
        out_lines.append(f"  [!] Error: {e}")
        sp.stop("Metadata extraction failed")
    log_section("9. METADATA & HIDDEN INFORMATION", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          10. WAF DETECTION                                               |
# +---------------------------------------------------------------------------+
def detect_waf(url: str, domain: str):
    sp = ScanProgress("WAF Detection")
    out_lines = []
    # -- wafw00f --
    sp.start("Running wafw00f WAF detector...")
    out_lines.append("  wafw00f Detection:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    live_print("Executing wafw00f...", "scan")
    waf00f_output = run_cmd(f"wafw00f {url} 2>/dev/null", timeout=60)
    if waf00f_output.strip():
        out_lines.append(f"    {waf00f_output.strip()}")
        if "is behind" in waf00f_output.lower():
            live_print("WAF detected by wafw00f!", "warn")
        else:
            live_print("wafw00f completed — no WAF detected", "info")
    else:
        out_lines.append("    [!] wafw00f not available or produced no output")
    sp.stop("wafw00f scan complete")
    # -- Manual WAF detection --
    sp.start("Performing manual WAF signature matching...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Manual WAF Detection:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    waf_signatures = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
            "body": ["cloudflare", "cf-browser-verification"],
            "server": ["cloudflare"],
        },
        "AWS WAF / CloudFront": {
            "headers": ["x-amz-cf-id", "x-amz-id-2", "x-amzn-requestid"],
            "cookies": ["awsalb", "awsalbcors"],
            "server": ["amazons3", "cloudfront"],
        },
        "Akamai": {
            "headers": ["x-akamai-transformed", "akamai-origin-hop"],
            "server": ["akamaighost", "akamai"],
        },
        "Imperva / Incapsula": {
            "headers": ["x-iinfo", "x-cdn"],
            "cookies": ["incap_ses", "visid_incap", "nlbi_"],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "server": ["sucuri"],
        },
        "F5 BIG-IP ASM": {
            "cookies": ["ts", "bigipserver"],
            "headers": ["x-wa-info"],
            "server": ["bigip", "big-ip"],
        },
        "ModSecurity": {
            "server": ["mod_security", "modsecurity"],
            "headers": ["x-modsecurity"],
        },
        "Barracuda": {
            "cookies": ["barra_counter_session"],
            "headers": ["barra_counter_session"],
        },
        "Fortinet FortiWeb": {
            "cookies": ["fortiwafsid"],
            "headers": ["fortiwafsid"],
        },
    }
    try:
        resp = safe_request(url)
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookies_str = str(resp.cookies.get_dict()).lower()
        server_header = headers_lower.get("server", "").lower()
        body_lower = resp.text[:5000].lower()
        detected = []
        total_wafs = len(waf_signatures)
        for idx, (waf_name, sigs) in enumerate(waf_signatures.items()):
            sp.update(
                detail=f"Checking {waf_name}...",
                scanned=idx + 1,
                total=total_wafs,
                found=len(detected),
            )
            found = False
            for h in sigs.get("headers", []):
                if h.lower() in headers_lower:
                    detected.append((waf_name, f"Header: {h}"))
                    found = True
                    break
            if not found:
                for c in sigs.get("cookies", []):
                    if c.lower() in cookies_str:
                        detected.append((waf_name, f"Cookie: {c}"))
                        found = True
                        break
            if not found:
                for s in sigs.get("server", []):
                    if s.lower() in server_header:
                        detected.append((waf_name, f"Server: {s}"))
                        found = True
                        break
            if not found:
                for b in sigs.get("body", []):
                    if b.lower() in body_lower:
                        detected.append((waf_name, f"Body pattern: {b}"))
                        found = True
                        break
        if detected:
            for waf, evidence in detected:
                out_lines.append(f"    [+] WAF DETECTED: {waf}  (Evidence: {evidence})")
                live_print(f"🛡️  WAF DETECTED: {waf} ({evidence})", "warn")
        else:
            out_lines.append("    [-] No WAF detected via signature matching.")
            live_print("No WAF detected via signatures", "info")
        sp.stop(f"Signature matching — {len(detected)} WAF(s) detected")
        # Trigger-based detection
        sp.start("Sending trigger payloads to detect WAF blocking...")
        out_lines.append(f"\n  {SUBSECTION_SEP}")
        out_lines.append("  Trigger-Based WAF Detection:")
        malicious_payloads = [
            ("XSS Test", "?test=<script>alert(1)</script>"),
            ("SQLi Test", "?id=1' OR '1'='1"),
            ("Path Traversal", "/../../../../etc/passwd"),
            ("Command Injection", "?cmd=;cat /etc/passwd"),
        ]
        blocked_count = 0
        for idx, (name, payload) in enumerate(malicious_payloads):
            sp.update(
                detail=f"Payload: {name}",
                scanned=idx + 1,
                total=len(malicious_payloads),
                found=blocked_count,
            )
            try:
                test_url = url.rstrip("/") + payload
                r = requests.get(
                    test_url, timeout=TIMEOUT, verify=False, allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                blocked = r.status_code in [403, 406, 429, 501, 502, 503]
                status = "BLOCKED" if blocked else f"Allowed ({r.status_code})"
                marker = "[WAF?]" if blocked else "[OK]"
                out_lines.append(f"    {marker} {name}: {status}")
                if blocked:
                    blocked_count += 1
                    live_print(f"Payload BLOCKED: {name} -> {r.status_code}", "warn")
                else:
                    live_print(f"Payload allowed: {name} -> {r.status_code}", "result")
            except Exception as e:
                out_lines.append(f"    [!] {name}: Error — {e}")
        sp.stop(f"Trigger test — {blocked_count}/{len(malicious_payloads)} blocked")
    except Exception as e:
        out_lines.append(f"  [!] Error: {e}")
        sp.stop("WAF detection failed")
    log_section("10. WEB APPLICATION FIREWALL (WAF) DETECTION", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          11. LOAD BALANCER DETECTION                                     |
# +---------------------------------------------------------------------------+
def detect_load_balancer(url: str, domain: str):
    sp = ScanProgress("Load Balancer Detection")
    out_lines = []
    # DNS-based
    sp.start("Testing DNS-based load balancing...")
    out_lines.append("  DNS-Based Load Balancer Detection:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        ips = set()
        for i in range(5):
            sp.update(detail=f"DNS query {i+1}/5...", scanned=i + 1, total=5)
            try:
                ip = socket.gethostbyname(domain)
                ips.add(ip)
                live_print(f"DNS query {i+1}: resolved to {ip}", "scan")
            except Exception:
                pass
            time.sleep(0.5)
        if dns:
            try:
                answers = dns.resolver.resolve(domain, "A")
                for a in answers:
                    ips.add(str(a))
            except Exception:
                pass
        out_lines.append(f"    Resolved IPs: {', '.join(ips)}")
        if len(ips) > 1:
            out_lines.append(
                f"    [+] LOAD BALANCER DETECTED: Multiple IPs ({len(ips)}) "
                f"indicate DNS round-robin or load balancing."
            )
            live_print(f"LOAD BALANCER: {len(ips)} unique IPs detected!", "warn")
        else:
            out_lines.append("    [-] Single IP detected (DNS-based LB not evident)")
        sp.stop(f"DNS check — {len(ips)} unique IPs")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("DNS check failed")
    # HTTP Header-based
    sp.start("Checking HTTP headers for load balancer indicators...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  HTTP Header-Based Detection:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    lb_indicators = {
        "X-Load-Balancer": "Generic Load Balancer",
        "X-Forwarded-For": "Proxy / Load Balancer",
        "X-Forwarded-Server": "Reverse Proxy / LB",
        "X-Forwarded-Host": "Reverse Proxy / LB",
        "Via": "Proxy / LB (Via header)",
        "X-Cache": "CDN / Caching LB",
        "X-Varnish": "Varnish Cache (often used as LB)",
        "X-Served-By": "Server identification behind LB",
        "X-Backend-Server": "Backend server identifier",
        "X-CDN": "CDN-based LB",
        "CF-RAY": "Cloudflare (CDN/LB)",
        "X-Amz-Cf-Id": "AWS CloudFront (CDN/LB)",
        "X-Azure-Ref": "Azure Front Door / LB",
        "X-Cache-Hits": "CDN Cache (indicates LB/CDN)",
    }
    try:
        resp = safe_request(url)
        found_lb = False
        total_ind = len(lb_indicators)
        for idx, (header, desc) in enumerate(lb_indicators.items()):
            sp.update(detail=f"Checking {header}...", scanned=idx + 1, total=total_ind)
            val = resp.headers.get(header)
            if val:
                out_lines.append(f"    [+] {header}: {val}  ({desc})")
                live_print(f"LB indicator: {header} = {val}", "found")
                found_lb = True
        if not found_lb:
            out_lines.append("    [-] No obvious LB headers detected.")
        sp.stop(f"Header check — {'indicators found' if found_lb else 'no indicators'}")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("Header check failed")
    # Response variation
    sp.start("Testing server response variation (5 requests)...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Response Variation Test (5 requests):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    servers = []
    try:
        for i in range(5):
            sp.update(detail=f"Request {i+1}/5...", scanned=i + 1, total=5)
            r = safe_request(url)
            srv = r.headers.get("Server", "N/A")
            date = r.headers.get("Date", "N/A")
            served_by = r.headers.get("X-Served-By", "")
            servers.append(srv)
            extra = f"  X-Served-By={served_by}" if served_by else ""
            out_lines.append(f"    Request {i+1}: Server={srv}  Date={date}{extra}")
            live_print(f"Request {i+1}: Server={srv}", "result")
            time.sleep(0.3)
        if len(set(servers)) > 1:
            out_lines.append(
                "    [+] LOAD BALANCER DETECTED: Server header varies between requests."
            )
            live_print("Server header VARIES — load balancer likely!", "warn")
        else:
            out_lines.append("    [-] Server header consistent across requests.")
        sp.stop(f"Variation test — {len(set(servers))} unique server value(s)")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("Variation test failed")
    # lbd tool
    sp.start("Running lbd tool...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  lbd Tool Output:")
    lbd_result = run_cmd(f"lbd {domain} 2>/dev/null", timeout=60)
    if lbd_result.strip() and "command not found" not in lbd_result.lower():
        out_lines.append(f"    {lbd_result.strip()}")
        sp.stop("lbd scan complete")
    else:
        out_lines.append("    [!] lbd not installed or not in PATH")
        sp.stop("lbd not available")
    log_section("11. LOAD BALANCER DETECTION", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          12. HTTP SERVICE DISCOVERY                                      |
# +---------------------------------------------------------------------------+
def http_service_discovery(url: str, domain: str):
    sp = ScanProgress("Service Discovery")
    out_lines = []
    ip = "N/A"
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        pass
    # Common ports
    sp.start("Scanning common web ports...")
    out_lines.append("  Common Web Ports Scan:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 3443, 4443, 5000,
                 5443, 9000, 9090, 9443, 8081, 8082, 8181, 8444, 2083, 2087]
    open_ports = 0
    total_ports = len(web_ports)
    for idx, port in enumerate(web_ports):
        sp.update(
            detail=f"Port {port}",
            scanned=idx + 1,
            total=total_ports,
            found=open_ports,
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip if ip != "N/A" else domain, port))
            if result == 0:
                open_ports += 1
                scheme = "https" if port in [443, 8443, 3443, 4443, 5443, 9443, 8444, 2083, 2087] else "http"
                try:
                    r = requests.get(
                        f"{scheme}://{domain}:{port}/",
                        timeout=5, verify=False, allow_redirects=False,
                    )
                    server = r.headers.get("Server", "Unknown")
                    title_match = re.search(r"<title>(.*?)</title>", r.text, re.I)
                    title = title_match.group(1) if title_match else "N/A"
                    out_lines.append(
                        f"    [OPEN] Port {port:5d} — Server: {server}  "
                        f"Title: {title[:50]}  Status: {r.status_code}"
                    )
                    live_print(f"Port {port} OPEN — {server} ({r.status_code})", "found")
                except Exception:
                    out_lines.append(f"    [OPEN] Port {port:5d} — (could not fetch HTTP)")
                    live_print(f"Port {port} OPEN (no HTTP response)", "found")
            sock.close()
        except Exception:
            pass
    sp.stop(f"Port scan — {open_ports} open ports found")
    # Nmap
    sp.start("Nmap scan (optional)")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Nmap HTTP Service Scan:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if os.getenv("ENABLE_NMAP", "0") == "1" and "nmap" in AVAILABLE_TOOLS:
        try:
            live_print("Executing lightweight nmap scan...", "scan")
            target_host = ip if ip != "N/A" else domain
            nmap_out = run_cmd(
                f"nmap -Pn -n -F -T4 --version-light --max-retries 0 --host-timeout 15s {target_host}",
                timeout=20,
            )
            if nmap_out.strip():
                out_lines.append(nmap_out)
            else:
                out_lines.append("    No Nmap output.")
            sp.stop("Nmap scan complete")
        except Exception as e:
            out_lines.append(f"    [!] Nmap scan error: {e}")
            sp.stop(f"Nmap error: {e}")
    else:
        out_lines.append("    [i] Nmap scan skipped by default for Windows stability.")
        out_lines.append("    [i] Set ENABLE_NMAP=1 to enable a short lightweight scan.")
        sp.stop("Nmap skipped")
    # Well-known endpoints
    sp.start("Probing well-known service endpoints...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Well-Known Service Endpoints:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    endpoints = [
        "/.well-known/security.txt", "/.well-known/openid-configuration",
        "/server-status", "/server-info", "/_status", "/health", "/healthz",
        "/api", "/api/v1", "/swagger.json", "/openapi.json",
        "/api-docs", "/graphql", "/graphiql", "/.env", "/info.php",
        "/phpinfo.php", "/wp-admin/", "/administrator/", "/admin/",
        "/login", "/wp-login.php", "/console", "/debug",
    ]
    ep_found = 0
    total_ep = len(endpoints)
    for idx, endpoint in enumerate(endpoints):
        sp.update(
            detail=f"Testing {endpoint}",
            scanned=idx + 1,
            total=total_ep,
            found=ep_found,
        )
        try:
            r = safe_request(urllib.parse.urljoin(url, endpoint), timeout=5)
            if r.status_code == 200:
                out_lines.append(f"    [200] {endpoint} ({len(r.text)} bytes)")
                live_print(f"Endpoint found: {endpoint} (200 OK)", "found")
                ep_found += 1
            elif r.status_code in [301, 302, 307, 308]:
                out_lines.append(
                    f"    [{r.status_code}] {endpoint} -> {r.headers.get('Location','')}"
                )
                ep_found += 1
            elif r.status_code == 403:
                out_lines.append(f"    [403] {endpoint} (Forbidden — exists but protected)")
                live_print(f"Endpoint exists (403): {endpoint}", "warn")
                ep_found += 1
        except Exception:
            pass
    sp.stop(f"Endpoint probe — {ep_found} endpoints discovered")
    log_section("12. HTTP SERVICE DISCOVERY", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          13. BANNER GRABBING                                             |
# +---------------------------------------------------------------------------+
def banner_grabbing(url: str, domain: str):
    sp = ScanProgress("Banner Grabbing")
    out_lines = []
    ip = "N/A"
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        pass
    # Raw socket banners
    sp.start("Grabbing HTTP banners via raw sockets...")
    out_lines.append("  HTTP Banner (via raw socket):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    http_ports = [80, 443, 8080, 8443]
    for idx, port in enumerate(http_ports):
        sp.update(
            detail=f"Port {port}",
            scanned=idx + 1,
            total=len(http_ports),
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            target = ip if ip != "N/A" else domain
            if port in [443, 8443]:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=domain)
            sock.connect((target, port))
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.send(request.encode())
            banner = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()
            out_lines.append(f"  Port {port}:")
            for line in banner.splitlines()[:15]:
                out_lines.append(f"    {line}")
            out_lines.append("")
            # Extract server line
            server_line = [l for l in banner.splitlines() if l.lower().startswith("server:")]
            if server_line:
                live_print(f"Port {port} banner: {server_line[0].strip()}", "found")
            else:
                live_print(f"Port {port} banner grabbed ({len(banner)} bytes)", "found")
        except Exception as e:
            out_lines.append(f"  Port {port}: Connection failed — {e}")
    sp.stop("Raw socket banners complete")
    # Requests library banner
    sp.start("Grabbing banner via requests library...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  HTTP Banner (via requests library):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        resp = safe_request(url)
        server = resp.headers.get('Server', 'N/A')
        powered = resp.headers.get('X-Powered-By', 'N/A')
        out_lines.append(f"    Server        : {server}")
        out_lines.append(f"    X-Powered-By  : {powered}")
        out_lines.append(f"    Content-Type  : {resp.headers.get('Content-Type', 'N/A')}")
        out_lines.append(f"    Status        : {resp.status_code}")
        live_print(f"Server: {server} | Powered-By: {powered}", "found")
        sp.stop(f"Banner: {server}")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("Banner grab failed")
    # Nmap banner
    sp.start("Running Nmap banner grab scripts...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Nmap Banner Grab:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if "nmap" in AVAILABLE_TOOLS:
        live_print("Executing nmap banner scripts...", "scan")
        nmap_out = run_cmd(
            f"nmap -sV -p 80,443 --script=banner "
            f"{ip if ip != 'N/A' else domain} 2>/dev/null",
            timeout=60,
        )
        out_lines.append(f"    {nmap_out.strip()}")
        sp.stop("Nmap banner scan complete")
    else:
        out_lines.append("    [!] nmap not available")
        sp.stop("nmap not available")
    # curl banner
    sp.start("Grabbing banner with curl...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  curl Banner:")
    if "curl" in AVAILABLE_TOOLS:
        curl_out = run_cmd(f"curl -sI -k {url} 2>/dev/null | head -20")
        out_lines.append(f"    {curl_out.strip()}")
        sp.stop("curl banner complete")
    else:
        out_lines.append("    [!] curl not available")
        sp.stop("curl not available")
    # Other service banners
    sp.start("Grabbing banners from other common services...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Other Service Banners:")
    other_ports = {21: "FTP", 22: "SSH", 25: "SMTP", 110: "POP3", 143: "IMAP"}
    total_other = len(other_ports)
    for idx, (port, service) in enumerate(other_ports.items()):
        sp.update(detail=f"{service} (port {port})", scanned=idx + 1, total=total_other)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            target = ip if ip != "N/A" else domain
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                out_lines.append(f"    [{service}] Port {port}: {banner[:200]}")
                live_print(f"{service} banner: {banner[:60]}", "found")
            sock.close()
        except Exception:
            pass
    sp.stop("Service banner grabbing complete")
    log_section("13. BANNER GRABBING", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          14. ENUMERATE WEB SERVER DIRECTORIES                            |
# +---------------------------------------------------------------------------+
def enumerate_directories(url: str, domain: str):
    sp = ScanProgress("Directory Enumeration")
    out_lines = []
    # Built-in brute force
    sp.start("Brute-forcing common directories and files...")
    out_lines.append("  Built-in Directory Brute Force:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    common_dirs = [
        "admin", "administrator", "login", "wp-admin", "wp-login.php",
        "wp-content", "wp-includes", "wp-json", "dashboard", "cpanel",
        "phpmyadmin", "pma", "mysql", "myadmin", "config", "configuration",
        "backup", "backups", "bak", "old", "temp", "tmp", "test", "testing",
        "dev", "development", "staging", "stage", "demo", "beta", "alpha",
        "api", "api/v1", "api/v2", "rest", "graphql", "swagger",
        "docs", "documentation", "help", "support", "faq",
        "images", "img", "assets", "static", "media", "uploads", "files",
        "css", "js", "javascript", "fonts", "vendor",
        "cgi-bin", "bin", "scripts", "includes", "inc",
        "data", "database", "db", "sql", "dump",
        "log", "logs", "error", "errors", "debug",
        "server-status", "server-info", "status", "health", "ping",
        "info.php", "phpinfo.php", "info", "xmlrpc.php",
        ".git", ".svn", ".env", ".htaccess", ".htpasswd",
        "web.config", "config.php", "wp-config.php", "configuration.php",
        "robots.txt", "sitemap.xml", "crossdomain.xml", "humans.txt",
        "security.txt", ".well-known", "favicon.ico",
        "user", "users", "account", "accounts", "profile", "register",
        "signup", "signin", "logout", "forgot", "reset",
        "search", "download", "downloads", "upload",
        "portal", "intranet", "extranet", "private", "public",
        "forum", "blog", "news", "press", "about", "contact",
        "terms", "privacy", "legal", "disclaimer",
        "cart", "shop", "store", "checkout", "order", "payment",
        "500", "404", "error", "403",
    ]
    found_dirs = []
    total_dirs = len(common_dirs)
    for idx, dirname in enumerate(common_dirs):
        sp.update(
            detail=f"/{dirname}",
            scanned=idx + 1,
            total=total_dirs,
            found=len(found_dirs),
        )
        test_url = f"{url.rstrip('/')}/{dirname}"
        try:
            r = requests.get(
                test_url, timeout=5, verify=False, allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
                },
            )
            if r.status_code == 200:
                found_dirs.append((dirname, 200, len(r.text)))
                out_lines.append(f"    [200] /{dirname} ({len(r.text)} bytes)")
                live_print(f"FOUND: /{dirname} -> 200 OK ({len(r.text)} bytes)", "found")
            elif r.status_code in [301, 302, 307, 308]:
                loc = r.headers.get("Location", "")
                found_dirs.append((dirname, r.status_code, loc))
                out_lines.append(f"    [{r.status_code}] /{dirname} -> {loc}")
                live_print(f"REDIRECT: /{dirname} -> {r.status_code}", "found")
            elif r.status_code == 403:
                found_dirs.append((dirname, 403, "Forbidden"))
                out_lines.append(f"    [403] /{dirname} (Forbidden — exists)")
                live_print(f"FORBIDDEN: /{dirname} -> 403 (exists!)", "warn")
            elif r.status_code == 401:
                found_dirs.append((dirname, 401, "Auth Required"))
                out_lines.append(f"    [401] /{dirname} (Auth Required — exists)")
                live_print(f"AUTH REQUIRED: /{dirname} -> 401", "warn")
        except Exception:
            pass
    out_lines.append(f"\n    Total directories/files found: {len(found_dirs)}")
    sp.stop(
        f"Brute-force complete — {len(found_dirs)} found out of {total_dirs} tested"
    )
    # Gobuster
    sp.start("Running Gobuster directory scanner...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Gobuster Scan:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if "gobuster" in AVAILABLE_TOOLS:
        wordlist_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
        ]
        wordlist = None
        for wp in wordlist_paths:
            if os.path.exists(wp):
                wordlist = wp
                break
        if wordlist:
            out_lines.append(f"    Using wordlist: {wordlist}")
            live_print(f"Gobuster using: {wordlist}", "scan")
            gobuster_out = run_cmd(
                f"gobuster dir -u {url} -w {wordlist} -t 20 -q "
                f"--no-error -k --timeout 10s 2>/dev/null | head -60",
                timeout=120,
            )
            out_lines.append(gobuster_out if gobuster_out.strip() else "    No results")
            sp.stop("Gobuster scan complete")
        else:
            out_lines.append("    [!] No wordlist found for gobuster")
            sp.stop("No wordlist found")
    else:
        out_lines.append("    [!] gobuster skipped on Windows (optional)")
        sp.stop("gobuster skipped on Windows (optional)")
    # Nikto
    sp.start("Running Nikto web vulnerability scanner...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Nikto Scan (quick):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    if "nikto" in AVAILABLE_TOOLS:
        live_print("Executing nikto (max 120s)...", "scan")
        nikto_out = run_cmd(
            f"nikto -h {url} -maxtime 120 -nointeractive 2>/dev/null | head -80",
            timeout=150,
        )
        out_lines.append(nikto_out if nikto_out.strip() else "    No results")
        sp.stop("Nikto scan complete")
    else:
        out_lines.append("    [!] nikto skipped on Windows (optional)")
        sp.stop("nikto skipped on Windows (optional)")
    log_section("14. WEB SERVER DIRECTORY ENUMERATION", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |          15. PROXY FUNCTIONALITY TEST                                    |
# +---------------------------------------------------------------------------+
def test_proxy_functionality(url: str, domain: str):
    sp = ScanProgress("Proxy Testing")
    out_lines = []
    ip = "N/A"
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        pass
    # HTTP CONNECT
    sp.start("Testing HTTP CONNECT method for open proxy...")
    out_lines.append("  HTTP CONNECT Method Test (Open Proxy):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    connect_ports = [80, 8080, 3128, 8888]
    for idx, port in enumerate(connect_ports):
        sp.update(
            detail=f"Port {port}",
            scanned=idx + 1,
            total=len(connect_ports),
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            target = ip if ip != "N/A" else domain
            result = sock.connect_ex((target, port))
            if result == 0:
                connect_req = (
                    f"CONNECT www.google.com:443 HTTP/1.1\r\n"
                    f"Host: www.google.com\r\n\r\n"
                )
                sock.send(connect_req.encode())
                response = sock.recv(4096).decode("utf-8", errors="replace")
                if "200" in response:
                    out_lines.append(
                        f"    [!] Port {port}: OPEN PROXY DETECTED — "
                        f"CONNECT method succeeded"
                    )
                    live_print(f"WARN️  OPEN PROXY on port {port}!", "warn")
                else:
                    first_line = response.split("\n")[0] if response else "No response"
                    out_lines.append(
                        f"    [-] Port {port}: CONNECT denied — {first_line.strip()}"
                    )
            else:
                out_lines.append(f"    [-] Port {port}: Not listening")
            sock.close()
        except Exception as e:
            out_lines.append(f"    [-] Port {port}: {e}")
    sp.stop("CONNECT method test complete")
    # Proxy headers
    sp.start("Detecting proxy-related headers in response...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Proxy-Related Headers Detection:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    proxy_headers = [
        "Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server",
        "X-Forwarded-Proto", "X-Real-IP", "X-Proxy-ID", "Proxy-Connection",
        "X-BlueCoat-Via", "X-Cache", "X-Cache-Lookup", "X-Squid-Error",
        "Forwarded",
    ]
    try:
        resp = safe_request(url)
        found_proxy = False
        for idx, h in enumerate(proxy_headers):
            sp.update(detail=f"Checking {h}...", scanned=idx + 1, total=len(proxy_headers))
            val = resp.headers.get(h)
            if val:
                out_lines.append(f"    [+] {h}: {val}")
                live_print(f"Proxy header: {h} = {val}", "found")
                found_proxy = True
        if not found_proxy:
            out_lines.append("    [-] No proxy-related headers found in response.")
        sp.stop(f"Proxy headers — {'found' if found_proxy else 'none detected'}")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("Proxy header check failed")
    # TRACE method
    sp.start("Testing TRACE method...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  TRACE Method Test:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        r = requests.request("TRACE", url, timeout=TIMEOUT, verify=False)
        if r.status_code == 200 and "TRACE" in r.text:
            out_lines.append(
                "    [!] TRACE method enabled — may indicate proxy or misconfiguration"
            )
            out_lines.append(f"    Response: {r.text[:500]}")
            live_print("TRACE method enabled — possible proxy!", "warn")
        else:
            out_lines.append(f"    [-] TRACE method returned {r.status_code}")
        sp.stop("TRACE test complete")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("TRACE test failed")
    # Open proxy forwarding test
    sp.start("Testing open proxy forwarding...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Open Proxy Test (forwarding external request):")
    out_lines.append(f"  {SUBSECTION_SEP}")
    try:
        proxy_test_url = "http://httpbin.org/ip"
        proxies = {"http": f"http://{domain}:80", "https": f"http://{domain}:8080"}
        try:
            r = requests.get(proxy_test_url, proxies=proxies, timeout=5)
            out_lines.append(f"    [!] Proxy may be open — response: {r.text[:200]}")
            live_print("Open proxy detected!", "warn")
        except Exception:
            out_lines.append(
                "    [-] Target does not appear to function as an open HTTP proxy"
            )
        sp.stop("Open proxy forwarding test complete")
    except Exception as e:
        out_lines.append(f"    [!] Error: {e}")
        sp.stop("Proxy forwarding test failed")
    # Proxy port scan
    sp.start("Scanning common proxy ports...")
    out_lines.append(f"\n  {SUBSECTION_SEP}")
    out_lines.append("  Common Proxy Port Scan:")
    out_lines.append(f"  {SUBSECTION_SEP}")
    proxy_ports = [
        (80, "HTTP"), (8080, "HTTP-Proxy"), (3128, "Squid"),
        (8888, "HTTP-Alt"), (1080, "SOCKS"), (9050, "Tor SOCKS"),
        (8118, "Privoxy"), (3129, "Squid-Alt"),
    ]
    open_proxy_ports = 0
    for idx, (port, desc) in enumerate(proxy_ports):
        sp.update(
            detail=f"{desc} (port {port})",
            scanned=idx + 1,
            total=len(proxy_ports),
            found=open_proxy_ports,
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            target = ip if ip != "N/A" else domain
            result = sock.connect_ex((target, port))
            if result == 0:
                out_lines.append(f"    [+] Port {port:5d} ({desc:12s}): OPEN")
                live_print(f"Proxy port OPEN: {port} ({desc})", "found")
                open_proxy_ports += 1
            sock.close()
        except Exception:
            pass
    sp.stop(f"Proxy port scan — {open_proxy_ports} open")
    log_section("15. PROXY FUNCTIONALITY TEST", "\n".join(out_lines))
# +---------------------------------------------------------------------------+
# |                       SAVE RESULTS                                       |
# +---------------------------------------------------------------------------+
def save_results(url: str, domain: str):
    """Save all gathered information to the output file."""
    header = f"""
{'#' * 80}
#
#   WEB INFORMATION GATHERING REPORT
#
#   Target URL    : {url}
#   Target Domain : {domain}
#   Scan Date     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
#   Report File   : {OUTPUT_FILE}
#
{'#' * 80}
"""
    footer = f"""
{SECTION_SEP}
  END OF REPORT
  Total sections: {len(results)}
  Generated at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{SECTION_SEP}
"""
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for section in results:
            f.write(section)
        f.write(footer)
    file_size = os.path.getsize(OUTPUT_FILE)
    print(Fore.CYAN + f"\n    [FILE] Report saved to : {os.path.abspath(OUTPUT_FILE)}")
    print(Fore.CYAN + f"    [SIZE] File size       : {file_size:,} bytes")
    print(Fore.CYAN + f"    [INFO] Sections        : {len(results)}")
# +---------------------------------------------------------------------------+
# |                        MAIN ENTRY POINT                                  |
# +---------------------------------------------------------------------------+
def main():
    import warnings
    warnings.filterwarnings("ignore")
    try:
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    except Exception:
        pass
    banner()
    cli_target = ""
    if len(sys.argv) > 1:
        # When launched from the Flask dashboard, the target is passed on the command line.
        cli_target = " ".join(sys.argv[1:]).strip()
    if cli_target:
        target = cli_target
        print(Fore.YELLOW + f"  [INFO] Target received from command line: {target}")
    else:
        # Manual terminal mode
        target = input(
            Fore.WHITE + Style.BRIGHT
            + "  [TARGET] Enter target URL (e.g., https://example.com): "
        ).strip()
    if not target:
        print(Fore.RED + "  [!] No URL provided. Exiting.")
        sys.exit(1)
    url = normalize_url(target)
    domain = extract_domain(url)
    print()
    print(Fore.CYAN + f"  +--------------------------------------------------+")
    print(Fore.CYAN + f"  |  Target URL    : {Fore.WHITE}{url:<32s}{Fore.CYAN}|")
    print(Fore.CYAN + f"  |  Domain        : {Fore.WHITE}{domain:<32s}{Fore.CYAN}|")
    print(Fore.CYAN + f"  |  Output File   : {Fore.WHITE}{OUTPUT_FILE:<32s}{Fore.CYAN}|")
    print(Fore.CYAN + f"  |  Started       : {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<32s}{Fore.CYAN}|")
    print(Fore.CYAN + f"  |  Tasks         : {Fore.WHITE}{'15 sequential tasks':<32s}{Fore.CYAN}|")
    print(Fore.CYAN + f"  +--------------------------------------------------+")
    if cli_target:
        confirm = "y"
    else:
        confirm = input(
            Fore.YELLOW
            + "\n  [!] Proceed with information gathering? (y/n): "
        ).strip().lower()
    if confirm not in ("y", "yes", ""):
        print(Fore.RED + "  [!] Aborted by user.")
        sys.exit(0)
    start_time = time.time()
    # Task definitions
    tasks = [
        ("Website Footprinting",          website_footprinting,         (url, domain)),
        ("Website Enumeration",           website_enumeration,          (url, domain)),
        ("HTML Source Code Analysis",      analyze_html_source,          (url,)),
        ("HTTP/HTML Processing Check",     check_http_processing,        (url,)),
        ("Server-Side Technologies",       identify_server_technologies, (url, domain)),
        ("Mirror & Crawl Website",         mirror_and_crawl,             (url, domain)),
        ("Sitemap Identification",         identify_sitemap,             (url,)),
        ("Common Word List Extraction",    extract_wordlist,             (url,)),
        ("Metadata & Hidden Information",  extract_metadata,             (url, domain)),
        ("WAF Detection",                  detect_waf,                   (url, domain)),
        ("Load Balancer Detection",        detect_load_balancer,         (url, domain)),
        ("HTTP Service Discovery",         http_service_discovery,       (url, domain)),
        ("Banner Grabbing",                banner_grabbing,              (url, domain)),
        ("Web Server Directory Enum",      enumerate_directories,        (url, domain)),
        ("Proxy Functionality Test",       test_proxy_functionality,     (url, domain)),
    ]
    tracker = TaskTracker(len(tasks))
    for i, (name, func, args) in enumerate(tasks, 1):
        try:
            tracker.begin_task(i, name)
            func(*args)
            tracker.complete_task(name)
        except KeyboardInterrupt:
            print(Fore.RED + "\n\n  [!] Interrupted by user. Saving partial results...")
            break
        except Exception as e:
            error_msg = f"  [!] Task failed with error: {e}"
            log_section(f"ERROR in {name}", error_msg)
            print(Fore.RED + error_msg)
    elapsed = time.time() - start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)
    print()
    print(Fore.CYAN + "  +------------------------------------------------------+")
    print(Fore.CYAN + "  |" + Fore.GREEN + Style.BRIGHT + "          SCAN COMPLETE — ALL TASKS FINISHED         " + Fore.CYAN + "|")
    print(Fore.CYAN + "  ╠------------------------------------------------------╣")
    print(Fore.CYAN + f"  |  Total Time    : {Fore.WHITE}{mins}m {secs}s{' ' * (33 - len(f'{mins}m {secs}s'))}{Fore.CYAN}|")
    print(Fore.CYAN + f"  |  Tasks Run     : {Fore.WHITE}{min(i, len(tasks))}/{len(tasks)}{' ' * (33 - len(f'{min(i, len(tasks))}/{len(tasks)}'))}{Fore.CYAN}|")
    print(Fore.CYAN + f"  |  Output File   : {Fore.WHITE}{OUTPUT_FILE}{' ' * (33 - len(OUTPUT_FILE))}{Fore.CYAN}|")
    print(Fore.CYAN + "  +------------------------------------------------------+")
    # Save everything
    save_results(url, domain)
    print(
        Fore.GREEN + Style.BRIGHT
        + "\n  [DONE] All results saved! Open "
        + Fore.CYAN + OUTPUT_FILE
        + Fore.GREEN + " to view the full report.\n"
    )
if __name__ == "__main__":
    main()