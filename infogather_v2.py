#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          INFORMATION GATHERING TOOL PRO v2.0                 ║
║          Cross-Platform Edition                              ║
║          IP | DNS | WHOIS | Ports | Subdomains               ║
║          Tech | OSINT | Auto Report (HTML/TXT/JSON)          ║
╠══════════════════════════════════════════════════════════════╣
║  Supports: Windows | Kali | Ubuntu | Parrot | Termux | iSH   ║
║  ⚠️  For Authorized / Educational Use Only                   ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import json
import sys
import os
import re
import argparse
import datetime
import subprocess
import platform
import concurrent.futures
import urllib.request
import urllib.parse

# ─────────────────────────────────────────
# PLATFORM DETECTION
# ─────────────────────────────────────────
SYSTEM = platform.system()  # Windows / Linux / Darwin
IS_WINDOWS = SYSTEM == "Windows"
IS_LINUX   = SYSTEM == "Linux"
IS_TERMUX  = "com.termux" in os.environ.get("PREFIX", "")
IS_ISH     = os.path.exists("/etc/ish-release") or "ish" in platform.release().lower()

def get_platform_name():
    if IS_TERMUX:  return "Termux (Android)"
    if IS_ISH:     return "iSH (iOS)"
    if IS_WINDOWS: return f"Windows {platform.release()}"
    dist = ""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME"):
                    dist = line.split("=")[1].strip().strip('"')
    except:
        dist = platform.platform()
    return dist or SYSTEM

# ─────────────────────────────────────────
# AUTO INSTALL MISSING LIBRARIES
# ─────────────────────────────────────────
def install_package(pkg):
    try:
        if IS_TERMUX:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=True)
        elif IS_WINDOWS:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"], check=True)
        else:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q",
                            "--break-system-packages"], check=True)
        return True
    except:
        return False

# Try importing requests
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    print("[!] requests not found. Installing...")
    if install_package("requests"):
        import requests
        requests.packages.urllib3.disable_warnings()
        HAS_REQUESTS = True
    else:
        HAS_REQUESTS = False

# ─────────────────────────────────────────
# COLORS (Windows compatible)
# ─────────────────────────────────────────
try:
    if IS_WINDOWS:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    COLOR_OK = True
except:
    COLOR_OK = False

class C:
    GREEN  = "\033[92m" if COLOR_OK or not IS_WINDOWS else ""
    RED    = "\033[91m" if COLOR_OK or not IS_WINDOWS else ""
    YELLOW = "\033[93m" if COLOR_OK or not IS_WINDOWS else ""
    CYAN   = "\033[96m" if COLOR_OK or not IS_WINDOWS else ""
    BLUE   = "\033[94m" if COLOR_OK or not IS_WINDOWS else ""
    BOLD   = "\033[1m"  if COLOR_OK or not IS_WINDOWS else ""
    RESET  = "\033[0m"  if COLOR_OK or not IS_WINDOWS else ""

def ok(msg):      print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def fail(msg):    print(f"  {C.RED}[-]{C.RESET} {msg}")
def info(msg):    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def found(msg):   print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def section(msg): print(f"\n{C.CYAN}{C.BOLD}[>] {msg}{C.RESET}")

# ─────────────────────────────────────────
# DATA STORE
# ─────────────────────────────────────────
report_data = {
    "target": "",
    "timestamp": "",
    "platform": "",
    "ip_info": {},
    "dns_info": {},
    "whois_info": {},
    "ports": [],
    "subdomains": [],
    "tech_info": {},
    "osint_info": {},
    "summary": {}
}

# ─────────────────────────────────────────
# WHOIS — Cross Platform
# ─────────────────────────────────────────
def run_whois(domain):
    """Cross-platform WHOIS query"""

    # Method 1: System whois command
    whois_cmd = "whois"
    try:
        result = subprocess.run(
            [whois_cmd, domain],
            capture_output=True, text=True, timeout=15
        )
        if result.stdout:
            return result.stdout
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Method 2: Raw socket WHOIS (works everywhere including Windows/iSH)
    try:
        # Get TLD whois server
        tld = domain.split(".")[-1]
        whois_servers = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "io":  "whois.nic.io",
            "co":  "whois.nic.co",
            "in":  "whois.registry.in",
            "uk":  "whois.nic.uk",
            "de":  "whois.denic.de",
            "sa":  "whois.nic.net.sa",
        }
        server = whois_servers.get(tld, "whois.iana.org")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode(errors="ignore")
    except Exception as e:
        return ""

# ─────────────────────────────────────────
# 1. IP INFO
# ─────────────────────────────────────────
def gather_ip_info(target):
    section("Gathering IP / Domain Info...")
    clean = re.sub(r'https?://', '', target).split("/")[0].split(":")[0]
    data = {}
    try:
        ip = socket.gethostbyname(clean)
        ok(f"Domain   : {clean}")
        ok(f"IP       : {ip}")
        data["domain"] = clean
        data["ip"] = ip

        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,query,timezone"
            if HAS_REQUESTS:
                r = requests.get(url, timeout=8)
                geo = r.json()
            else:
                with urllib.request.urlopen(url, timeout=8) as r:
                    geo = json.loads(r.read().decode())

            for field in ["country", "regionName", "city", "isp", "org", "timezone"]:
                val = geo.get(field, "")
                if val:
                    ok(f"{field.capitalize():10}: {val}")
                    data[field] = val
        except Exception as e:
            info(f"GeoIP lookup failed: {e}")

        report_data["ip_info"] = data
        report_data["summary"]["IP_INFO"] = "Done"
    except Exception as e:
        fail(f"IP lookup failed: {e}")
        report_data["summary"]["IP_INFO"] = "Failed"

# ─────────────────────────────────────────
# 2. DNS INFO
# ─────────────────────────────────────────
def gather_dns_info(target):
    section("Gathering DNS Records...")
    clean = re.sub(r'https?://', '', target).split("/")[0].split(":")[0]
    dns_data = {}

    # A Record
    try:
        results = socket.getaddrinfo(clean, None)
        ips = list(set([r[4][0] for r in results]))
        dns_data["A"] = ips
        for ip in ips:
            ok(f"A Record : {ip}")
    except Exception as e:
        info(f"A record lookup failed: {e}")

    # MX, NS, TXT via nslookup (cross-platform)
    for rtype in ["MX", "NS", "TXT"]:
        try:
            if IS_WINDOWS:
                cmd = ["nslookup", f"-type={rtype}", clean]
            else:
                cmd = ["nslookup", f"-type={rtype}", clean]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            lines = [l.strip() for l in result.stdout.split("\n")
                     if l.strip() and not l.startswith("Server") and not l.startswith("Address")
                     and clean.lower() not in l.lower()[:20]]
            if lines:
                dns_data[rtype] = lines[:5]
                for l in lines[:3]:
                    ok(f"{rtype:4} : {l[:70]}")
        except Exception:
            pass

    report_data["dns_info"] = dns_data
    report_data["summary"]["DNS"] = "Done" if dns_data else "Limited"

# ─────────────────────────────────────────
# 3. WHOIS
# ─────────────────────────────────────────
def gather_whois(target):
    section("Gathering WHOIS Info...")
    clean = re.sub(r'https?://', '', target).split("/")[0].split(":")[0]
    whois_data = {}

    output = run_whois(clean)

    if output:
        patterns = {
            "Registrar":          r"Registrar:\s*(.+)",
            "Creation Date":      r"Creation Date:\s*(.+)",
            "Expiry Date":        r"(?:Registry Expiry|Expiry) Date:\s*(.+)",
            "Updated Date":       r"Updated Date:\s*(.+)",
            "Registrant Org":     r"Registrant Organization:\s*(.+)",
            "Registrant Country": r"Registrant Country:\s*(.+)",
            "Name Server":        r"Name Server:\s*(.+)",
            "Status":             r"Domain Status:\s*(.+)",
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                val = matches[0].strip()
                whois_data[key] = val
                ok(f"{key}: {val[:60]}")

        if not whois_data:
            info("WHOIS returned data but no standard fields found")
            whois_data["raw_preview"] = output[:300]
    else:
        info("WHOIS unavailable — Install: pkg install whois / apt install whois")

    report_data["whois_info"] = whois_data
    report_data["summary"]["WHOIS"] = "Done" if whois_data else "Not available"

# ─────────────────────────────────────────
# 4. PORT SCANNER
# ─────────────────────────────────────────
def scan_ports(target):
    section("Scanning Ports...")
    clean = re.sub(r'https?://', '', target).split("/")[0].split(":")[0]

    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 8888: "HTTP-Dev", 27017: "MongoDB",
        9200: "Elasticsearch", 5000: "Flask/Dev", 4443: "HTTPS-Alt2"
    }

    open_ports = []

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((clean, port))
            sock.close()
            return port, result == 0
        except:
            return port, False

    try:
        ip = socket.gethostbyname(clean)
        info(f"Scanning {ip} ({len(common_ports)} ports)...")
        max_workers = 30 if IS_TERMUX or IS_ISH else 100

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_port, p): p for p in common_ports}
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    svc = common_ports[port]
                    found(f"Port {port:5} OPEN  ->  {svc}")
                    open_ports.append({"port": port, "service": svc, "status": "OPEN"})

        if not open_ports:
            info("No common ports found open")
        else:
            ok(f"Total open ports: {len(open_ports)}")

        report_data["ports"] = sorted(open_ports, key=lambda x: x["port"])
        report_data["summary"]["PORTS"] = f"{len(open_ports)} open"
    except Exception as e:
        fail(f"Port scan error: {e}")
        report_data["summary"]["PORTS"] = "Failed"

# ─────────────────────────────────────────
# 5. SUBDOMAIN FINDER
# ─────────────────────────────────────────
def find_subdomains(target):
    section("Finding Subdomains...")
    clean = re.sub(r'https?://', '', target).split("/")[0].split(":")[0]
    base = re.sub(r'^www\.', '', clean)

    common_subs = [
        "www", "mail", "ftp", "admin", "blog", "dev", "test", "api",
        "shop", "store", "portal", "vpn", "remote", "staging", "app",
        "secure", "login", "cpanel", "webmail", "m", "mobile", "beta",
        "old", "new", "support", "help", "docs", "status", "cdn",
        "cloud", "static", "assets", "media", "img", "smtp", "pop",
        "imap", "ns1", "ns2", "mx", "forum", "wiki", "git", "jenkins"
    ]

    found_subs = []

    def check_sub(sub):
        full = f"{sub}.{base}"
        try:
            ip = socket.gethostbyname(full)
            return full, ip
        except:
            return None, None

    info(f"Checking {len(common_subs)} subdomains for {base}...")
    max_workers = 20 if IS_TERMUX or IS_ISH else 50

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_sub, s): s for s in common_subs}
        for future in concurrent.futures.as_completed(futures):
            sub, ip = future.result()
            if sub:
                found(f"Found: {sub}  ->  {ip}")
                found_subs.append({"subdomain": sub, "ip": ip})

    if not found_subs:
        info("No subdomains found")
    else:
        ok(f"Total subdomains: {len(found_subs)}")

    report_data["subdomains"] = found_subs
    report_data["summary"]["SUBDOMAINS"] = f"{len(found_subs)} found"

# ─────────────────────────────────────────
# 6. TECH DETECTOR
# ─────────────────────────────────────────
def detect_tech(target):
    section("Detecting Website Technologies...")
    if not target.startswith("http"):
        target = "https://" + target

    tech_data = {}
    detected = []

    try:
        if HAS_REQUESTS:
            r = requests.get(target, timeout=12, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
            headers = dict(r.headers)
            body = r.text
            status = r.status_code
        else:
            req = urllib.request.Request(target,
                headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                headers = dict(resp.headers)
                body = resp.read().decode(errors="ignore")
                status = resp.status

        ok(f"HTTP Status   : {status}")
        tech_data["HTTP_Status"] = status

        for h in ["Server", "X-Powered-By", "Via", "X-Generator", "X-Drupal-Cache"]:
            val = headers.get(h) or headers.get(h.lower(), "")
            if val:
                ok(f"{h:20}: {val}")
                tech_data[h] = val

        cms_patterns = {
            "WordPress":    ["wp-content", "wp-includes", "wordpress"],
            "Joomla":       ["joomla", "/components/com_"],
            "Drupal":       ["drupal", "sites/default"],
            "Shopify":      ["shopify", "cdn.shopify"],
            "Wix":          ["wix.com", "_wix_"],
            "Squarespace":  ["squarespace"],
            "Laravel":      ["laravel", "XSRF-TOKEN"],
            "Django":       ["csrfmiddlewaretoken", "django"],
            "Ruby on Rails":["rails", "csrf-token"],
            "ASP.NET":      ["asp.net", "__viewstate", "aspnetform"],
            "PHP":          ["php", ".php"],
            "React":        ["react", "__NEXT_DATA__"],
            "Angular":      ["ng-version", "angular"],
            "Vue.js":       ["vue", "__vue__"],
            "Bootstrap":    ["bootstrap.min.css", "bootstrap.min.js"],
            "jQuery":       ["jquery.min.js", "jquery-"],
            "Cloudflare":   ["cloudflare", "__cfduid", "cf-ray"],
            "Nginx":        ["nginx"],
            "Apache":       ["apache"],
        }

        body_lower = body.lower()
        headers_str = str(headers).lower()

        for tech, patterns in cms_patterns.items():
            for p in patterns:
                if p.lower() in body_lower or p.lower() in headers_str:
                    ok(f"Detected      : {tech}")
                    detected.append(tech)
                    break

        tech_data["Technologies"] = detected
        report_data["tech_info"] = tech_data
        report_data["summary"]["TECH"] = f"{len(detected)} detected"
    except Exception as e:
        fail(f"Tech detection error: {e}")
        report_data["summary"]["TECH"] = "Failed"

# ─────────────────────────────────────────
# 7. OSINT
# ─────────────────────────────────────────
def gather_osint(target):
    section("OSINT — Email / Phone / Social Media...")
    if not target.startswith("http"):
        target = "https://" + target

    osint_data = {"emails": [], "phones": [], "social": []}

    try:
        if HAS_REQUESTS:
            r = requests.get(target, timeout=12, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            body = r.text
        else:
            req = urllib.request.Request(target,
                headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read().decode(errors="ignore")

        # Emails
        emails = list(set(re.findall(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", body
        )))
        emails = [e for e in emails if not any(x in e.lower()
                  for x in ["@2x", "@3x", ".png", ".jpg", ".svg",
                             "example", "schema", "sentry", "w3.org"])]
        for e in emails[:10]:
            found(f"Email  : {e}")
        osint_data["emails"] = emails[:10]

        # Phones
        phones = list(set(re.findall(
            r"[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?"
            r"[-\s\.]?[0-9]{3,4}[-\s\.]?[0-9]{3,4}", body
        )))
        phones = [p.strip() for p in phones if len(re.sub(r'\D','',p)) >= 7]
        for p in phones[:5]:
            found(f"Phone  : {p}")
        osint_data["phones"] = phones[:5]

        # Social
        social_patterns = {
            "LinkedIn":  r"linkedin\.com/(?:in|company)/[^\s\"'<>/]+",
            "Twitter":   r"twitter\.com/[^\s\"'<>/]+",
            "Facebook":  r"facebook\.com/[^\s\"'<>/]+",
            "Instagram": r"instagram\.com/[^\s\"'<>/]+",
            "YouTube":   r"youtube\.com/(?:c|channel|user)/[^\s\"'<>/]+",
            "GitHub":    r"github\.com/[^\s\"'<>/]+",
            "Telegram":  r"t\.me/[^\s\"'<>/]+",
        }

        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                found(f"{platform:12}: {matches[0][:60]}")
                osint_data["social"].append({
                    "platform": platform,
                    "url": matches[0][:80]
                })

        if not emails and not phones and not osint_data["social"]:
            info("No public contact info found on homepage")

        report_data["osint_info"] = osint_data
        report_data["summary"]["OSINT"] = (
            f"{len(emails)} emails, {len(phones)} phones, "
            f"{len(osint_data['social'])} social"
        )
    except Exception as e:
        fail(f"OSINT error: {e}")
        report_data["summary"]["OSINT"] = "Failed"

# ─────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────
def generate_html(filename):
    target = report_data["target"]
    ts = report_data["timestamp"]
    plat = report_data["platform"]

    cards = ""
    for k, v in report_data["summary"].items():
        color = "#27ae60" if "Failed" not in v and "Not" not in v else "#e74c3c"
        cards += (f'<div class="card" style="border-left:4px solid {color}">'
                  f'<b>{k}</b><br><span style="color:{color};font-size:.9em">{v}</span></div>')

    def make_table(rows_data, headers):
        if not rows_data:
            return "<p style='color:#8b949e'>No data found</p>"
        th = "".join(f"<th>{h}</th>" for h in headers)
        rows = ""
        for row in rows_data:
            rows += "<tr>" + "".join(f"<td>{v}</td>" for v in row.values()) + "</tr>"
        return f"<table><tr>{th}</tr>{rows}</table>"

    ip_rows = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>"
                      for k, v in report_data["ip_info"].items())
    whois_rows = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>"
                         for k, v in report_data["whois_info"].items()
                         if k != "raw_preview")
    port_rows = "".join(
        f'<tr><td><b>{p["port"]}</b></td>'
        f'<td style="color:#27ae60">{p["service"]}</td>'
        f'<td style="color:#27ae60">OPEN</td></tr>'
        for p in report_data["ports"]
    ) or "<tr><td colspan='3' style='color:#8b949e'>No open ports found</td></tr>"

    sub_rows = "".join(
        f'<tr><td style="color:#3498db">{s["subdomain"]}</td><td>{s["ip"]}</td></tr>'
        for s in report_data["subdomains"]
    ) or "<tr><td colspan='2' style='color:#8b949e'>None found</td></tr>"

    tech = report_data["tech_info"]
    tech_rows = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>"
                        for k, v in tech.items())

    osint = report_data["osint_info"]
    email_list = "".join(f"<li>📧 {e}</li>" for e in osint.get("emails", []))
    phone_list = "".join(f"<li>📞 {p}</li>" for p in osint.get("phones", []))
    social_list = "".join(
        f'<li>🔗 <b>{s["platform"]}</b>: {s["url"]}</li>'
        for s in osint.get("social", [])
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>InfoGather Pro - {target}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
  h1{{color:#58a6ff;border-bottom:2px solid #21262d;padding-bottom:12px;margin-bottom:15px;font-size:1.6em}}
  h2{{color:#79c0ff;margin:25px 0 10px;border-left:4px solid #2563eb;padding-left:10px;font-size:1.1em}}
  .meta{{background:#161b22;padding:14px;border-radius:8px;margin:12px 0;font-size:.9em}}
  .meta span{{margin-right:20px;color:#8b949e}}
  .meta b{{color:#e6edf3}}
  .cards{{display:flex;flex-wrap:wrap;gap:10px;margin:15px 0}}
  .card{{background:#161b22;border-radius:8px;padding:10px 15px;min-width:120px;font-size:.85em}}
  table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:.88em}}
  th{{background:#21262d;color:#8b949e;padding:8px 12px;text-align:left;font-size:.8em;text-transform:uppercase}}
  td{{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-all}}
  tr:hover{{background:rgba(255,255,255,.02)}}
  ul{{margin:6px 0 6px 20px}}
  li{{padding:3px 0;font-size:.88em}}
  .footer{{text-align:center;color:#30363d;font-size:.72em;margin-top:35px;padding-top:15px;border-top:1px solid #21262d}}
  .warn{{background:rgba(231,76,60,.1);border-left:4px solid #e74c3c;padding:10px 15px;border-radius:4px;font-size:.85em;margin:10px 0}}
</style>
</head>
<body>
<h1>🔍 Information Gathering Report</h1>
<div class="warn">⚠️ For Educational & Authorized Use Only — Only gather info on systems you own or have permission to test.</div>
<div class="meta">
  <span>🎯 <b>Target:</b> {target}</span>
  <span>🕐 <b>Time:</b> {ts}</span>
  <span>💻 <b>Platform:</b> {plat}</span>
</div>

<h2>📋 Summary</h2>
<div class="cards">{cards}</div>

<h2>🌐 IP / GeoLocation Info</h2>
<table><tr><th>Field</th><th>Value</th></tr>{ip_rows}</table>

<h2>📄 WHOIS Info</h2>
<table><tr><th>Field</th><th>Value</th></tr>
{whois_rows or "<tr><td colspan='2' style='color:#8b949e'>Not available</td></tr>"}
</table>

<h2>🔓 Open Ports</h2>
<table><tr><th>Port</th><th>Service</th><th>Status</th></tr>{port_rows}</table>

<h2>🌍 Subdomains</h2>
<table><tr><th>Subdomain</th><th>IP Address</th></tr>{sub_rows}</table>

<h2>⚙️ Technologies Detected</h2>
<table><tr><th>Field</th><th>Details</th></tr>{tech_rows}</table>

<h2>🔎 OSINT — Contact Info</h2>
<b>Emails:</b>
<ul>{email_list or "<li style='color:#8b949e'>None found</li>"}</ul>
<b>Phone Numbers:</b>
<ul>{phone_list or "<li style='color:#8b949e'>None found</li>"}</ul>
<b>Social Media:</b>
<ul>{social_list or "<li style='color:#8b949e'>None found</li>"}</ul>

<div class="footer">
  InfoGather Pro v2.0 | Cross-Platform Edition<br>
  Windows | Kali | Ubuntu | Parrot | Termux | iSH<br>
  For Authorized & Educational Use Only
</div>
</body></html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  {C.GREEN}[+] HTML Report: {filename}{C.RESET}")

def generate_txt(filename):
    sep = "=" * 62
    lines = [sep, "       INFORMATION GATHERING REPORT — v2.0", sep,
             f"Target   : {report_data['target']}",
             f"Time     : {report_data['timestamp']}",
             f"Platform : {report_data['platform']}", sep,
             "\nSUMMARY:"]
    for k, v in report_data["summary"].items():
        lines.append(f"  {k:15}: {v}")
    lines += ["\nIP / DOMAIN INFO:", "-" * 40]
    for k, v in report_data["ip_info"].items():
        lines.append(f"  {k:15}: {v}")
    lines += ["\nWHOIS:", "-" * 40]
    for k, v in report_data["whois_info"].items():
        if k != "raw_preview":
            lines.append(f"  {k:20}: {v}")
    lines += ["\nOPEN PORTS:", "-" * 40]
    if report_data["ports"]:
        for p in report_data["ports"]:
            lines.append(f"  {p['port']:5}  {p['service']:20} OPEN")
    else:
        lines.append("  No open ports found")
    lines += ["\nSUBDOMAINS:", "-" * 40]
    if report_data["subdomains"]:
        for s in report_data["subdomains"]:
            lines.append(f"  {s['subdomain']:35} -> {s['ip']}")
    else:
        lines.append("  None found")
    lines += ["\nTECHNOLOGIES:", "-" * 40]
    for k, v in report_data["tech_info"].items():
        lines.append(f"  {k:20}: {v}")
    lines += ["\nOSINT:", "-" * 40]
    for e in report_data["osint_info"].get("emails", []):
        lines.append(f"  Email  : {e}")
    for p in report_data["osint_info"].get("phones", []):
        lines.append(f"  Phone  : {p}")
    for s in report_data["osint_info"].get("social", []):
        lines.append(f"  {s['platform']:12}: {s['url']}")
    lines += ["\n" + sep, "For authorized & educational use only."]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  {C.GREEN}[+] TXT Report: {filename}{C.RESET}")

def generate_json(filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print(f"  {C.GREEN}[+] JSON Report: {filename}{C.RESET}")

# ─────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────
def banner(plat):
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║          INFORMATION GATHERING TOOL PRO v2.0                 ║
║          Cross-Platform Edition                              ║
╠══════════════════════════════════════════════════════════════╣
║  Windows | Kali | Ubuntu | Parrot | Termux | iSH             ║
║  ⚠️  For Authorized / Educational Use Only                   ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}
  Platform: {C.GREEN}{plat}{C.RESET}
""")

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main():
    plat = get_platform_name()
    banner(plat)

    parser = argparse.ArgumentParser(
        description="InfoGather Pro v2.0 — Cross-Platform Information Gathering Tool"
    )
    parser.add_argument("target", help="Target domain or URL (e.g. example.com)")
    parser.add_argument("--modules", nargs="+",
                        choices=["ip","dns","whois","ports","subdomains","tech","osint"],
                        default=["ip","dns","whois","ports","subdomains","tech","osint"])
    parser.add_argument("--report", nargs="+",
                        choices=["html","txt","json"],
                        default=["html","txt","json"])
    parser.add_argument("--output", default="reports",
                        help="Output folder (default: reports/)")
    args = parser.parse_args()

    target = args.target.strip()
    ts = datetime.datetime.now()

    report_data["target"] = target
    report_data["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S")
    report_data["platform"] = plat

    print(f"  {C.CYAN}Target   : {target}{C.RESET}")
    print(f"  {C.CYAN}Time     : {report_data['timestamp']}{C.RESET}")
    print(f"  {C.CYAN}Platform : {plat}{C.RESET}")

    if "ip"         in args.modules: gather_ip_info(target)
    if "dns"        in args.modules: gather_dns_info(target)
    if "whois"      in args.modules: gather_whois(target)
    if "ports"      in args.modules: scan_ports(target)
    if "subdomains" in args.modules: find_subdomains(target)
    if "tech"       in args.modules: detect_tech(target)
    if "osint"      in args.modules: gather_osint(target)

    print(f"\n{C.BOLD}{'─'*50}")
    print("  SCAN COMPLETE - SUMMARY")
    print(f"{'─'*50}{C.RESET}")
    for k, v in report_data["summary"].items():
        c = C.GREEN if "Failed" not in v and "Not" not in v else C.RED
        print(f"  {c}[{k}]{C.RESET} {v}")

    os.makedirs(args.output, exist_ok=True)
    safe = re.sub(r'[^\w]', '_', target.replace("https://","").replace("http://",""))[:30]
    stamp = ts.strftime("%Y%m%d_%H%M%S")
    base = os.path.join(args.output, f"infogather_{safe}_{stamp}")

    print(f"\n{C.CYAN}{C.BOLD}[>] Generating Reports...{C.RESET}")
    if "html" in args.report: generate_html(base + ".html")
    if "txt"  in args.report: generate_txt(base + ".txt")
    if "json" in args.report: generate_json(base + ".json")

    print(f"\n  {C.GREEN}Reports saved in: {os.path.abspath(args.output)}/{C.RESET}\n")

if __name__ == "__main__":
    main()