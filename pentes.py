#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pentes.py v3.0 — Accurate Web Vulnerability Scanner (Termux Edition)
=====================================================================
Design principles (v3.0):
  - ACCURACY FIRST: no finding without verbatim evidence
  - HONEST: every finding has confidence + reason
  - WAF-AWARE: skips audit on error pages, detects blocks
  - STRICT default + AGGRESSIVE opt-in (--aggressive)

Features:
  STRICT MODE (default):
    - Security headers & cookie flags
    - CORS misconfiguration
    - HTTP methods
    - Sensitive file discovery (content-validated)
    - GET injection tests (only on existing params)
    - Fingerprint + WAF detect
    - GraphQL introspection

  AGGRESSIVE MODE (--aggressive):
    - Parameter discovery (Arjun-style, 100+ common params)
    - Recursive crawler (depth 3, 50 URLs)
    - robots.txt + sitemap.xml harvest
    - Form extraction + POST injection testing
    - WordPress enumeration (users, xmlrpc, readme, plugins)
    - Backup file discovery (.bak, .old, .swp, .tmp, ~)
    - WAF bypass tamper for SQLi/XSS
    - Directory listing detection
    - Debug mode detection

  BOTH MODES:
    - Time-based SQLi (3-tier linear correlation)
    - Reflected XSS (executable context verified)
    - LFI (content signature verified)
    - Open Redirect (Location header verified)
    - Custom headers / cookies / auth

For authorized penetration testing only.
"""

import os
import re
import sys
import json
import time
import random
import string
import socket
import threading
import argparse
import hashlib
import traceback
from datetime import datetime
from urllib.parse import (
    urlparse, urljoin, urlencode, parse_qs, urlunparse,
)
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# DEPENDENCIES
# ============================================================
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] pip install beautifulsoup4")
    sys.exit(1)

try:
    from colorama import init as _ci
    _ci(autoreset=False)
except ImportError:
    pass


# ============================================================
# COLORS
# ============================================================
class C:
    R       = "\033[0m"
    B       = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[38;5;196m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[38;5;226m"
    BLUE    = "\033[38;5;39m"
    CYAN    = "\033[38;5;51m"
    GREEN   = "\033[38;5;46m"
    MAGENTA = "\033[38;5;201m"
    WHITE   = "\033[38;5;255m"
    GRAY    = "\033[38;5;240m"


SEVERITY_ORDER = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}
SEVERITY_COLOR = {
    "CRITICAL": C.RED, "HIGH": C.ORANGE, "MEDIUM": C.YELLOW,
    "LOW": C.BLUE, "INFO": C.CYAN,
}
CONF_ORDER = {"CONFIRMED": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
CONF_COLOR = {
    "CONFIRMED": C.GREEN, "HIGH": C.CYAN,
    "MEDIUM": C.YELLOW, "LOW": C.GRAY,
}

PRINT_LOCK = threading.Lock()


def sp(*args, **kwargs):
    with PRINT_LOCK:
        print(*args, **kwargs)


def rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ============================================================
# FINDING MODEL
# ============================================================
class Finding:
    def __init__(self, severity, confidence, vtype, url, description,
                 evidence="", reason=""):
        self.severity    = severity
        self.confidence  = confidence
        self.vtype       = vtype
        self.url         = url
        self.description = description
        self.evidence    = evidence
        self.reason      = reason
        self.timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {
            "severity": self.severity, "confidence": self.confidence,
            "type": self.vtype, "url": self.url,
            "description": self.description, "evidence": self.evidence,
            "reason": self.reason, "timestamp": self.timestamp,
        }

    def render(self):
        sc = SEVERITY_COLOR.get(self.severity, C.WHITE)
        cc = CONF_COLOR.get(self.confidence, C.WHITE)
        lines = [
            f"{sc}{C.B}┌─ [{self.severity}] {self.vtype}  {cc}[conf:{self.confidence}]{sc}{C.R}",
            f"{sc}│{C.R}  {C.DIM}URL      :{C.R} {self.url}",
            f"{sc}│{C.R}  {C.DIM}Impact   :{C.R} {self.description}",
        ]
        if self.reason:
            lines.append(f"{sc}│{C.R}  {C.DIM}Reason   :{C.R} {self.reason}")
        if self.evidence:
            ev = self.evidence.replace("\n", f"\n{sc}│{C.R}             ")
            lines.append(f"{sc}│{C.R}  {C.DIM}Evidence :{C.R} {ev}")
        lines.append(f"{sc}└{'─' * 64}{C.R}")
        return "\n".join(lines)


# ============================================================
# URL UTILS
# ============================================================
def normalize_target(raw):
    raw = (raw or "").strip().strip("'\"")
    if not raw:
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        return raw
    first = raw.split("/")[0]
    if "." in first or re.match(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$", first):
        return "https://" + raw
    if re.match(r"^[A-Za-z0-9-]+$", raw):
        return f"https://{raw}.com"
    return "https://" + raw


def get_root(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def same_host(url, base):
    return urlparse(url).netloc == urlparse(base).netloc


def extract_params(url):
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def with_param(url, param, value):
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse((p.scheme, p.netloc, p.path, p.params,
                       urlencode(params, doseq=True), p.fragment))


def add_param(url, param, value):
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    if param in params:
        return None  # already exists
    params[param] = [value]
    return urlunparse((p.scheme, p.netloc, p.path, p.params,
                       urlencode(params, doseq=True), p.fragment))


# ============================================================
# WAF / ERROR PAGE DETECTION
# ============================================================
CF_ERROR_PATTERNS = [
    r"cf-error-details", r"Error\s*10\d{2}", r"Error\s*5\d{2}",
    r"Just a moment\.\.\.", r"Attention Required!\s*\|\s*Cloudflare",
    r"origin web server is not reachable", r"Web server is down",
    r"Origin DNS error", r"checking your browser before accessing",
    r"cf-browser-verification", r"__cf_chl_",
    r"Access denied\s*\|\s*Cloudflare",
    r"This website is using a security service",
    r"Please enable cookies",
    r"Request unsuccessful. Incapsula",
    r"/cdn-cgi/challenge-platform/",
]


def is_error_page(resp):
    if resp is None:
        return True
    if resp.status_code >= 500:
        return True
    body = (resp.text or "")[:8000]
    for pat in CF_ERROR_PATTERNS:
        if re.search(pat, body, re.I):
            return True
    if "cf-mitigated" in {k.lower() for k in resp.headers}:
        return True
    return False


def is_waf_block(resp):
    """Detect active WAF block specifically (403 + WAF signature)."""
    if resp is None:
        return False
    if resp.status_code not in (403, 406, 429, 503):
        return False
    body = (resp.text or "")[:5000].lower()
    waf_signs = ["cloudflare", "access denied", "just a moment",
                 "incapsula", "sucuri", "akamai", "captcha",
                 "request blocked", "forbidden"]
    return any(s in body for s in waf_signs)


def detect_waf(resp):
    if resp is None:
        return None
    h = {k.lower(): v for k, v in resp.headers.items()}
    server = h.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in h:
        return "Cloudflare"
    if "sucuri" in server:
        return "Sucuri"
    if "akamai" in server or "x-akamai-transformed" in h:
        return "Akamai"
    if "aws" in server or "x-amz-cf-id" in h:
        return "AWS CloudFront"
    if "incapdns" in server:
        return "Imperva"
    return None


# ============================================================
# RESPONSE SIGNATURE (for param discovery & comparisons)
# ============================================================
def response_sig(resp):
    if resp is None:
        return None
    body = (resp.text or "")[:8000]
    key_h = ["content-type", "location", "x-powered-by"]
    hdr_sig = "|".join(f"{k}={resp.headers.get(k, '')}" for k in key_h)
    return {
        "status": resp.status_code,
        "length": len(resp.content),
        "hash": hashlib.md5(body.encode("utf-8", errors="ignore")).hexdigest(),
        "hdr": hdr_sig,
    }


def sigs_differ(a, b, len_tol=0.05, min_len_diff=80):
    if a is None or b is None:
        return False
    if a["status"] != b["status"]:
        return True
    if abs(a["length"] - b["length"]) > max(min_len_diff, a["length"] * len_tol):
        return True
    if a["hash"] != b["hash"] and abs(a["length"] - b["length"]) > 20:
        return True
    if a["hdr"] != b["hdr"]:
        return True
    return False


# ============================================================
# HTTP CLIENT
# ============================================================
class HTTPClient:
    def __init__(self, timeout=12, delay=0.0, retries=1,
                 headers=None, cookies=None, verbose=False):
        self.session = requests.Session()
        default_ua = ("Mozilla/5.0 (Linux; Android 13; SM-G991B) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Mobile Safari/537.36")
        self.session.headers.update({
            "User-Agent": default_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if headers:
            for h in headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.session.headers[k.strip()] = v.strip()
        if cookies:
            self.session.headers["Cookie"] = cookies
        self.session.verify = False
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.verbose = verbose

    def _log(self, method, url, resp, elapsed):
        if not self.verbose:
            return
        status = resp.status_code if resp is not None else "ERR"
        size = len(resp.content) if resp is not None else 0
        sp(f"{C.GRAY}[V] {method:<4} {url[:110]}  →  {status}  {size}B  {elapsed:.2f}s{C.R}")

    def _do(self, method, url, **kw):
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        last = None
        for attempt in range(self.retries + 1):
            if self.delay:
                time.sleep(self.delay)
            t0 = time.time()
            try:
                r = self.session.request(method, url, **kw)
                self._log(method, url, r, time.time() - t0)
                # Backoff on rate limit
                if r.status_code == 429 and attempt < self.retries:
                    time.sleep(2 + attempt)
                    continue
                return r
            except requests.RequestException as e:
                self._log(method, url, None, time.time() - t0)
                last = e
                if attempt < self.retries:
                    time.sleep(0.5)
        return None

    def get(self, url, **kw):
        return self._do("GET", url, **kw)

    def post(self, url, **kw):
        return self._do("POST", url, **kw)

    def head(self, url, **kw):
        return self._do("HEAD", url, **kw)

    def options(self, url, **kw):
        return self._do("OPTIONS", url, **kw)


# ============================================================
# FINGERPRINT
# ============================================================
TECH_PATTERNS = {
    "WordPress":  [r"/wp-content/", r"/wp-includes/", r"/wp-json/"],
    "Joomla":     [r"/components/com_", r"/media/system/js/"],
    "Drupal":     [r"Drupal\.settings", r"/sites/default/files/"],
    "Magento":    [r"Mage\.Cookies", r"/skin/frontend/"],
    "Laravel":    [r"laravel_session", r"XSRF-TOKEN"],
    "Django":     [r"csrftoken", r"__admin__"],
    "Express.js": [r"X-Powered-By:\s*Express"],
    "React":      [r"data-reactroot", r"__REACT"],
    "Vue.js":     [r"data-v-[0-9a-f]{6,}", r"vue\.runtime"],
    "Angular":    [r"ng-version=", r"ng-app="],
    "jQuery":     [r"jquery[-.]\d+\.\d+.*\.js"],
    "Bootstrap":  [r"bootstrap(\.min)?\.(css|js)"],
    "Next.js":    [r"__NEXT_DATA__", r"/_next/static/"],
    "Nuxt":       [r"__NUXT__", r"/_nuxt/"],
    "Shopify":    [r"cdn\.shopify\.com"],
    "PHP":        [r"PHPSESSID", r"\.php\?"],
    "ASP.NET":    [r"ASP\.NET_SessionId", r"__VIEWSTATE"],
}


def scan_fingerprint(client, url):
    findings = []
    r = client.get(url)
    if r is None or is_error_page(r):
        return findings
    body = (r.text or "")[:200000]
    hdr_str = " ".join(f"{k}: {v}" for k, v in r.headers.items())
    haystack = (body + " " + hdr_str).lower()

    detected = []
    for tech, pats in TECH_PATTERNS.items():
        for p in pats:
            if re.search(p, haystack, re.I):
                detected.append(tech)
                break

    waf = detect_waf(r)
    if waf:
        detected.append(f"{waf} (WAF)")
    server = r.headers.get("Server")
    if server and server.lower() not in ("", "cloudflare"):
        detected.append(f"Server: {server}")

    if detected:
        findings.append(Finding(
            "INFO", "CONFIRMED", "Technology Fingerprint", url,
            "Stack teknologi terdeteksi (berguna untuk cari CVE spesifik).",
            "Terdeteksi: " + ", ".join(dict.fromkeys(detected)),
            "Signature cocok di HTML atau header respons."
        ))
    return findings


# ============================================================
# SECURITY HEADERS
# ============================================================
HEADER_CHECKS = {
    "Content-Security-Policy": (
        "MEDIUM", "CSP absen → tidak ada pembatasan sumber script/style, "
                  "memperparah dampak XSS."
    ),
    "Strict-Transport-Security": (
        "MEDIUM", "HSTS absen → rentan SSL-strip / downgrade ke HTTP."
    ),
    "X-Frame-Options": (
        "MEDIUM", "X-Frame-Options absen → clickjacking via iframe."
    ),
    "X-Content-Type-Options": (
        "LOW", "Tanpa 'nosniff' → risiko MIME-sniffing XSS."
    ),
    "Referrer-Policy": (
        "LOW", "Referrer-Policy absen → URL/token bisa bocor via Referer."
    ),
    "Permissions-Policy": (
        "LOW", "Permissions-Policy absen → fitur sensitif tidak dibatasi."
    ),
}


def scan_security_headers(client, url):
    findings = []
    r = client.get(url)
    if r is None:
        return [Finding(
            "INFO", "CONFIRMED", "Connection Failed", url,
            "Tidak dapat connect ke target.", "requests error / DNS / timeout."
        )]

    if r.status_code >= 500 or is_error_page(r):
        return [Finding(
            "INFO", "CONFIRMED", "Header Audit SKIPPED — Origin Unreachable", url,
            "Server mengembalikan halaman error (Cloudflare/WAF/origin down). "
            "Audit header DI-SKIP karena respons bukan dari website asli.",
            f"HTTP {r.status_code}  |  Server: {r.headers.get('Server', '-')}",
            "Mengukur header pada error page = false positive, jadi sengaja dilewati."
        )]

    present = {k.lower(): v for k, v in r.headers.items()}
    for name, (sev, desc) in HEADER_CHECKS.items():
        if name.lower() not in present:
            findings.append(Finding(
                sev, "CONFIRMED", f"Missing {name}", url, desc,
                f"Header '{name}' tidak ada pada HTTP {r.status_code} response.",
                "Header benar-benar tidak dikirim oleh server (bukan error page)."
            ))

    # Cookie flags
    try:
        set_cookies = r.raw.headers.getlist("Set-Cookie") or []
    except Exception:
        set_cookies = []
    for ck in set_cookies:
        name = ck.split("=", 1)[0].strip()
        low = ck.lower()
        missing = []
        if "httponly" not in low: missing.append("HttpOnly")
        if "secure" not in low:   missing.append("Secure")
        if "samesite" not in low: missing.append("SameSite")
        if missing:
            findings.append(Finding(
                "MEDIUM", "HIGH",
                f"Cookie Missing Flags ({', '.join(missing)})", url,
                f"Cookie '{name}' tanpa {', '.join(missing)} → rentan "
                f"session hijack via XSS / sniffing / CSRF.",
                f"Set-Cookie: {ck[:200]}",
                "Cookie dikirim server tanpa flag proteksi yang diharapkan."
            ))

    if "X-Powered-By" in r.headers:
        findings.append(Finding(
            "LOW", "CONFIRMED", "Technology Disclosure (X-Powered-By)", url,
            "X-Powered-By membocorkan stack backend.",
            f"X-Powered-By: {r.headers.get('X-Powered-By')}",
            "Header ada di response, terverifikasi."
        ))
    return findings


# ============================================================
# CORS
# ============================================================
def scan_cors(client, url):
    findings = []
    probe_origin = "https://evil.pentes.invalid"
    r = client.get(url, headers={"Origin": probe_origin})
    if r is None or is_error_page(r):
        return findings
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == probe_origin and acac == "true":
        findings.append(Finding(
            "HIGH", "CONFIRMED", "CORS Misconfiguration (credentials)", url,
            "ACAO reflects arbitrary Origin + ACAC=true → attacker dapat "
            "membaca data user yang sedang login (session theft).",
            f"Request Origin: {probe_origin}\nResponse ACAO: {acao}\nResponse ACAC: {acac}",
            "Origin arbitrer direfleksikan + credentials diizinkan (kombinasi paling bahaya)."
        ))
    elif acao == probe_origin:
        findings.append(Finding(
            "MEDIUM", "CONFIRMED", "CORS Misconfiguration (reflected origin)", url,
            "ACAO reflects arbitrary Origin → konten bisa dibaca cross-origin.",
            f"Request Origin: {probe_origin}\nResponse ACAO: {acao}",
            "Server memantulkan Origin yang dikirim tanpa validasi whitelist."
        ))
    elif acao == "*" and acac == "true":
        findings.append(Finding(
            "MEDIUM", "CONFIRMED", "CORS Wildcard with Credentials", url,
            "ACAO='*' + ACAC=true → misconfiguration kontradiktif.",
            f"ACAO: {acao}\nACAC: {acac}",
            "Kombinasi wildcard + credentials dilarang spec, tapi menunjukkan salah konfigurasi."
        ))
    return findings


# ============================================================
# HTTP METHODS
# ============================================================
def scan_methods(client, url):
    findings = []
    r = client.options(url)
    if r is None or is_error_page(r):
        return findings
    allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods", "")
    if not allow:
        return findings
    methods = [m.strip().upper() for m in allow.split(",")]
    if "TRACE" in methods:
        findings.append(Finding(
            "LOW", "CONFIRMED", "TRACE Method Enabled", url,
            "TRACE dapat disalahgunakan untuk Cross-Site Tracing.",
            f"Allow: {allow}",
            "Header Allow mengonfirmasi TRACE diizinkan."
        ))
    risky = [m for m in methods if m in ("PUT", "DELETE", "PATCH")]
    if risky:
        findings.append(Finding(
            "INFO", "CONFIRMED", "Risky HTTP Methods Enabled", url,
            f"Method {', '.join(risky)} diizinkan. Pastikan benar-benar diperlukan.",
            f"Allow: {allow}",
            "Header Allow menyebut method berisiko (informasi, bukan kerentanan per se)."
        ))
    return findings


# ============================================================
# DIRECTORY / SENSITIVE FILES (CONTENT-VALIDATED)
# ============================================================
# Format: path -> (severity, description, content_signature_regex_list)
SENSITIVE_PATHS = {
    ".env": ("CRITICAL", "Kredensial & API keys bocor (DB, JWT, cloud).",
             [r"^[A-Z_][A-Z0-9_]*\s*=\s*\S", r"APP_KEY=", r"DB_PASSWORD="]),
    ".env.bak": ("CRITICAL", "Backup .env → secret bocor.",
                 [r"^[A-Z_][A-Z0-9_]*\s*=\s*\S"]),
    ".env.local": ("CRITICAL", ".env.local terbuka.",
                   [r"^[A-Z_][A-Z0-9_]*\s*="]),
    ".git/config": ("CRITICAL", "Git config bocor → URL remote + kredensial.",
                    [r"\[core\]", r"repositoryformatversion"]),
    ".git/HEAD": ("HIGH", "Git repo terbuka → source rekonstruksi.",
                  [r"^ref:\s+refs/", r"^[0-9a-f]{40}"]),
    "wp-config.php": ("CRITICAL", "wp-config terbaca → kredensial DB.",
                      [r"<\?php", r"DB_PASSWORD", r"DB_NAME"]),
    "wp-config.php.bak": ("CRITICAL", "Backup wp-config.",
                          [r"<\?php", r"DB_PASSWORD"]),
    "backup.sql": ("CRITICAL", "SQL dump terbuka.",
                   [r"CREATE TABLE", r"INSERT INTO"]),
    "db.sql": ("CRITICAL", "DB dump terbuka.",
               [r"CREATE TABLE", r"INSERT INTO"]),
    "dump.sql": ("CRITICAL", "SQL dump terbuka.",
                 [r"CREATE TABLE", r"INSERT INTO"]),
    "id_rsa": ("CRITICAL", "SSH private key terbuka.",
               [r"-----BEGIN\s+(RSA\s+|OPENSSH\s+|)PRIVATE KEY-----"]),
    ".htpasswd": ("CRITICAL", ".htpasswd terbuka.",
                  [r"^[A-Za-z0-9_.-]+:\$"]),
    "shell.php": ("CRITICAL", "Kemungkinan webshell.",
                  [r"eval\s*\(", r"system\s*\(", r"shell_exec"]),
    "config.php": ("HIGH", "Config PHP terbuka.",
                   [r"<\?php", r"password", r"db_"]),
    "config.json": ("HIGH", "Config JSON terbuka.",
                    [r'"\w*password\w*"\s*:', r'"\w*secret\w*"\s*:', r'"\w*api[_-]?key\w*"\s*:']),
    "web.config": ("HIGH", "IIS web.config terbuka.",
                   [r"<configuration", r"<connectionStrings"]),
    "phpinfo.php": ("MEDIUM", "phpinfo() → bocor path/env/versi.",
                    [r"phpinfo\(\)", r"PHP Version"]),
    "info.php": ("MEDIUM", "Info page bocor environment.",
                 [r"PHP Version", r"phpinfo"]),
    "server-status": ("MEDIUM", "Apache server-status terbuka.",
                      [r"Apache Server Status"]),
    "server-info": ("MEDIUM", "Apache server-info terbuka.",
                    [r"Apache Server Information"]),
    "swagger.json": ("MEDIUM", "Swagger spec → API endpoint leaked.",
                     [r'"swagger":', r'"openapi":']),
    "api-docs": ("MEDIUM", "API docs terbuka.",
                 [r"swagger", r"openapi"]),
    "phpmyadmin/": ("MEDIUM", "phpMyAdmin terekspos.",
                    [r"phpMyAdmin", r"pma_password"]),
    "robots.txt": ("INFO", "robots.txt → bisa reveal hidden path.",
                   [r"User-agent:", r"Disallow:", r"Sitemap:"]),
    "sitemap.xml": ("INFO", "Sitemap terekspos.",
                    [r"<urlset", r"<sitemapindex"]),
    ".htaccess": ("LOW", ".htaccess terekspos.",
                  [r"RewriteRule", r"Options", r"<Files"]),
    "crossdomain.xml": ("LOW", "Cek kebijakan crossdomain permissive.",
                        [r"<cross-domain-policy"]),
    "README.md": ("INFO", "README terekspos.", [r"#\s", r"##\s"]),
    "CHANGELOG.md": ("LOW", "Changelog → reveal versi/CVE.",
                     [r"##\s*\[?\d"]),
    "security.txt": ("INFO", "security.txt tersedia.", [r"Contact:"]),
    ".well-known/security.txt": ("INFO", "security.txt tersedia.", [r"Contact:"]),
    "graphql": ("INFO", "Endpoint GraphQL ada.",
                [r'"data":', r'"errors":', r"__schema"]),
    "login": ("INFO", "Halaman login ditemukan.", [r"<form", r"password"]),
    "login.php": ("INFO", "Halaman login ditemukan.", [r"<form", r"password"]),
    "admin/": ("INFO", "Panel admin terdeteksi.",
               [r"<form", r"password", r"login", r"dashboard"]),
    "administrator/": ("INFO", "Panel admin Joomla.",
                       [r"<form", r"Joomla", r"password"]),
    "cgi-bin/": ("LOW", "Direktori cgi-bin ada.",
                 [r"Index of", r"Parent Directory"]),
}

BINARY_SIGS = {
    "backup.zip":    ("CRITICAL", "Arsip backup webroot terbuka.", b"PK\x03\x04"),
    "site.zip":      ("CRITICAL", "Arsip site terbuka.", b"PK\x03\x04"),
    "www.zip":       ("CRITICAL", "Arsip webroot terbuka.", b"PK\x03\x04"),
    "backup.tar.gz": ("CRITICAL", "Arsip backup terbuka.", b"\x1f\x8b"),
    "db.sql.gz":     ("CRITICAL", "DB dump terkompresi terbuka.", b"\x1f\x8b"),
}


class DirScanner:
    def __init__(self, client, base_url, threads=20, aggressive=False):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.threads = threads
        self.aggressive = aggressive
        self.baseline_status = None
        self.baseline_len = None
        self.soft404 = False
        self._calibrate()

    def _calibrate(self):
        samples = []
        for _ in range(3):
            rnd = rand_str(20)
            r = self.client.get(f"{self.base_url}/{rnd}")
            if r is None:
                continue
            samples.append((r.status_code, len(r.content)))
        if not samples:
            self.baseline_status = 404
            self.baseline_len = 0
            return
        statuses = [s[0] for s in samples]
        lengths = [s[1] for s in samples]
        self.baseline_status = max(set(statuses), key=statuses.count)
        self.baseline_len = int(sum(lengths) / len(lengths))
        if len(set(statuses)) == 1 and self.baseline_status == 200:
            self.soft404 = True

    def _is_soft404(self, resp):
        if not self.soft404:
            return False
        if resp.status_code != self.baseline_status:
            return False
        if self.baseline_len == 0:
            return len(resp.content) < 500
        ratio = len(resp.content) / max(self.baseline_len, 1)
        return 0.9 < ratio < 1.1

    def _validate_content(self, resp, sigs):
        if not sigs:
            return False
        body = resp.text or ""
        return any(re.search(p, body, re.I | re.M) for p in sigs)

    def _validate_binary(self, resp, magic):
        return resp.content.startswith(magic)

    def test_one(self, path):
        url = f"{self.base_url}/{path}"
        r = self.client.get(url)
        if r is None:
            return None
        if is_error_page(r):
            return None
        if self._is_soft404(r):
            return None

        if r.status_code in (401, 403):
            if path not in SENSITIVE_PATHS and path not in BINARY_SIGS:
                return None
            return Finding(
                "INFO", "CONFIRMED", f"Path Exists (Protected): /{path}", url,
                "Path ditemukan tapi dilindungi (401/403). Tidak ada bukti "
                "kebocoran konten. Ini BUKAN kerentanan.",
                f"HTTP {r.status_code}  |  Size: {len(r.content)}B",
                "Status 401/403 = akses ditolak. Tidak ada bukti ekspos."
            )

        if r.status_code not in (200, 201, 204, 301, 302, 303, 307, 308):
            return None

        if path in BINARY_SIGS:
            sev, desc, magic = BINARY_SIGS[path]
            if r.status_code in (301, 302, 303, 307, 308):
                r2 = self.client.get(url)
                if r2 is None or is_error_page(r2):
                    return None
                r = r2
            if self._validate_binary(r, magic):
                return Finding(
                    sev, "CONFIRMED", f"Sensitive File Exposed: /{path}", url,
                    desc,
                    f"HTTP {r.status_code}  |  Size: {len(r.content)}B  |  "
                    f"Magic bytes match: {magic.hex()}",
                    "Magic bytes file cocok persis dengan arsip terkompresi."
                )
            return None

        if path not in SENSITIVE_PATHS:
            return None

        sev, desc, sigs = SENSITIVE_PATHS[path]

        # FIX v3.0: dir dengan trailing slash WAJIB validasi konten juga
        if path.endswith("/"):
            if not self._validate_content(r, sigs):
                return None  # v2.0 bug fixed — tidak lapor tanpa bukti
            snippet = (r.text or "")[:200].replace("\n", " ").strip()
            return Finding(
                "INFO", "CONFIRMED", f"Directory Discovered: /{path}", url, desc,
                f"HTTP {r.status_code}  |  Size: {len(r.content)}B\nSnippet: {snippet}",
                "Konten direktori mengandung signature yang diharapkan (form/login/dll)."
            )

        if self._validate_content(r, sigs):
            snippet = (r.text or "")[:300].replace("\n", " ").strip()
            return Finding(
                sev, "CONFIRMED", f"Sensitive File Exposed: /{path}", url, desc,
                f"HTTP {r.status_code}  |  Size: {len(r.content)}B\n"
                f"Content signature matched.\nSnippet: {snippet}",
                "Status 200 + isi file cocok dengan signature yang diharapkan."
            )

        # 200 tapi signature tidak cocok → INFO low, jangan klaim vuln
        if sev in ("CRITICAL", "HIGH"):
            return Finding(
                "INFO", "LOW", f"Path Responds but Content Unverified: /{path}", url,
                "Path mengembalikan 200 tapi isi tidak cocok dengan signature. "
                "Kemungkinan soft-404, custom error, atau WAF. Tidak dianggap temuan.",
                f"HTTP {r.status_code}  |  Size: {len(r.content)}B\n"
                f"Snippet: {(r.text or '')[:120]}",
                "Isi tidak cocok dengan pattern file yang diharapkan."
            )
        return None

    def run(self):
        results = []
        paths = list(SENSITIVE_PATHS.keys()) + list(BINARY_SIGS.keys())
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.test_one, p): p for p in paths}
            for fut in as_completed(futures):
                try:
                    f = fut.result()
                except Exception:
                    f = None
                if f:
                    results.append(f)
                    sp(f.render())
        return results


# ============================================================
# BACKUP FILE DISCOVERY (AGGRESSIVE)
# ============================================================
BACKUP_EXTS = [".bak", ".old", ".tmp", ".swp", ".save", ".orig", "~", ".1", ".2"]


def scan_backup_files(client, base_url, known_files, threads=15):
    """Untuk setiap file yang diketahui, coba ekstensi backup."""
    findings = []
    if not known_files:
        return findings

    def test(item):
        path = item
        url = f"{base_url.rstrip('/')}/{path}"
        r = client.get(url)
        if r is None or is_error_page(r):
            return None
        if r.status_code != 200:
            return None
        # Validate: should have content (not soft-404 already filtered by DirScanner)
        text = r.text or ""
        if len(text.strip()) < 20:
            return None
        snippet = text[:200].replace("\n", " ").strip()
        return Finding(
            "MEDIUM", "HIGH", f"Backup File Accessible: /{path}", url,
            "File backup terekspos → source code / config bisa dibaca.",
            f"HTTP {r.status_code}  |  Size: {len(r.content)}B\nSnippet: {snippet}",
            "Status 200 dengan konten non-kosong (bukan soft-404)."
        )

    tasks = []
    for f in known_files:
        if f.endswith("/"):
            continue
        for ext in BACKUP_EXTS:
            tasks.append(f"{f}{ext}")
        # Linux-style hidden backup: .file.swp
        dirname = os.path.dirname(f)
        basename = os.path.basename(f)
        if dirname:
            tasks.append(f"{dirname}/.{basename}.swp")
        else:
            tasks.append(f".{basename}.swp")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(test, p) for p in tasks]
        for fut in as_completed(futures):
            try:
                f = fut.result()
            except Exception:
                f = None
            if f:
                findings.append(f)
                sp(f.render())
    return findings


# ============================================================
# DIRECTORY LISTING & DEBUG DETECTION
# ============================================================
def scan_directory_listing(client, base_url):
    findings = []
    paths = ["", "uploads/", "images/", "files/", "backup/", "logs/",
             "wp-content/", "wp-content/uploads/", "wp-content/plugins/",
             "wp-content/themes/", "static/", "assets/", "media/"]
    for p in paths:
        url = f"{base_url.rstrip('/')}/{p}"
        r = client.get(url)
        if r is None or is_error_page(r):
            continue
        if r.status_code != 200:
            continue
        body = r.text or ""
        if re.search(r"<title>\s*Index of /", body, re.I) or \
           re.search(r"<h1>\s*Index of /", body, re.I):
            findings.append(Finding(
                "MEDIUM", "CONFIRMED", "Directory Listing Enabled", url,
                "Web server menampilkan isi direktori → attacker bisa enumerasi "
                "file (backup, source, data).",
                f"HTTP {r.status_code}\nSignature: 'Index of /' di <title> atau <h1>",
                "Halaman persis berisi 'Index of /' — auto-index aktif."
            ))
    return findings


def scan_debug_disclosure(client, base_url):
    findings = []
    probes = [
        ("/?debug=1", [r"Stack trace", r"DEBUG\s*=\s*True", r"Whoops",
                       r"Laravel.*Exception", r"Traceback \(most recent call last\)"]),
        ("/__debug__", [r"debug", r"stack"]),
        ("/nonexistent_pentes_" + rand_str(6),
         [r"Traceback \(most recent call last\)", r"Whoops",
          r"Stack trace:", r"Django.*DEBUG\s*=\s*True",
          r"Fatal error:.*on line \d+"]),
    ]
    for path, sigs in probes:
        url = base_url.rstrip("/") + path
        r = client.get(url)
        if r is None or is_error_page(r):
            continue
        body = r.text or ""
        for sig in sigs:
            if re.search(sig, body, re.I):
                findings.append(Finding(
                    "MEDIUM", "CONFIRMED", "Debug Mode / Verbose Error Disclosure", url,
                    "Aplikasi menampilkan detail error / stack trace → attacker "
                    "mendapat info path, versi, config.",
                    f"Signature: '{sig}' cocok di response body.",
                    "Pola stack trace / debug marker terdeteksi verbatim."
                ))
                break
    return findings


# ============================================================
# ROBOTS / SITEMAP HARVEST
# ============================================================
def harvest_robots_sitemap(client, base_url):
    paths = set()
    try:
        r = client.get(f"{base_url.rstrip('/')}/robots.txt")
        if r is not None and r.status_code == 200 and not is_error_page(r):
            for line in (r.text or "").splitlines():
                m = re.match(r"^\s*(Disallow|Allow|Sitemap)\s*:\s*(.+)$", line, re.I)
                if m:
                    val = m.group(2).strip()
                    if val and val != "/":
                        paths.add(val.lstrip("/"))
    except Exception:
        pass
    try:
        r = client.get(f"{base_url.rstrip('/')}/sitemap.xml")
        if r is not None and r.status_code == 200 and not is_error_page(r):
            for m in re.finditer(r"<loc>\s*([^<]+)\s*</loc>", r.text or ""):
                u = m.group(1).strip()
                p = urlparse(u)
                if p.path:
                    paths.add(p.path.lstrip("/"))
                    if p.query:
                        paths.add(p.path.lstrip("/") + "?" + p.query)
    except Exception:
        pass
    return paths


# ============================================================
# CRAWLER (RECURSIVE)
# ============================================================
def crawl_recursive(client, start_url, max_depth=2, max_urls=40, verbose=False):
    seen = {start_url}
    queue = [(start_url, 0)]
    all_urls = [start_url]
    base_host = urlparse(start_url).netloc

    while queue and len(all_urls) < max_urls:
        url, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        r = client.get(url)
        if r is None or is_error_page(r):
            continue
        ctype = r.headers.get("Content-Type", "").lower()
        if "html" not in ctype:
            continue
        try:
            soup = BeautifulSoup(r.text or "", "html.parser")
        except Exception:
            continue
        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"].split("#")[0])
            if not full.startswith(("http://", "https://")):
                continue
            if urlparse(full).netloc != base_host:
                continue
            if full in seen:
                continue
            seen.add(full)
            all_urls.append(full)
            if len(all_urls) >= max_urls:
                break
            queue.append((full, depth + 1))
    return all_urls


def extract_param_urls_from(urls):
    out = set()
    for u in urls:
        if "?" in u and extract_params(u):
            out.add(u)
    return out


# ============================================================
# FORM EXTRACTION & POST TESTING
# ============================================================
def extract_forms(client, url):
    r = client.get(url)
    if r is None or is_error_page(r):
        return []
    ctype = r.headers.get("Content-Type", "").lower()
    if "html" not in ctype:
        return []
    try:
        soup = BeautifulSoup(r.text or "", "html.parser")
    except Exception:
        return []
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action") or url)
        method = (form.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            continue
        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype in ("submit", "button", "image", "reset", "file"):
                continue
            val = inp.get("value", "test")
            if inp.name == "textarea":
                val = "test"
            inputs[name] = val
        if inputs:
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "source_url": url,
            })
    return forms


# ============================================================
# INJECTION: GET + POST, WITH ACCURACY CONTROLS
# ============================================================
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*?MySQL", r"Warning.*?mysql_",
    r"MySQLSyntaxErrorException", r"valid MySQL result",
    r"PostgreSQL.*?ERROR", r"pg_query\(\)\s*\[",
    r"SQLite/JDBCDriver", r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"ORA-01756", r"ORA-00933", r"ORA-00921",
    r"syntax error at or near",
    r"You have an error in your SQL syntax",
]

SQLI_ERROR_PAYLOADS = ["'", "\"", "')", "';"]

SQLI_BOOL_PAIRS = [
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 'a'='a", "' OR 'a'='b"),
]

SQLI_TIME_PAYLOADS = [1, 3, 5]

XSS_MARKER_TEMPLATE = "<svg/onload=alert('PENTES_{m}')>"

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "../../../../windows/win.ini",
    "../../../../etc/passwd%00",
]
LFI_INDICATORS = [
    "root:x:0:0", "root:*:0:0", "daemon:x:", "bin:x:",
    "[extensions]", "for 16-bit app support",
]

REDIRECT_PARAMS = {
    "url", "redirect", "next", "return", "returnurl", "redir",
    "destination", "dest", "go", "goto", "target", "r", "u",
    "link", "out", "callback", "continue", "redirect_uri",
}

# WAF bypass tamper (basic)
def tamper_variants(payload):
    """Generate variant payloads to try bypassing WAF."""
    variants = [payload]
    variants.append(payload.replace("'", "%27"))
    variants.append(payload.replace("'", "%2527"))
    variants.append(payload.replace(" ", "/**/"))
    variants.append(payload.replace(" ", "+"))
    variants.append(payload.replace("SLEEP", "SLE/**/EP"))
    variants.append(payload.replace("SLEEP", "sleep"))
    return list(dict.fromkeys(variants))  # preserve order, dedupe


def inject_marker(text, marker):
    """Check if marker appears literally in text (unescaped)."""
    return marker in (text or "")


class InjectionScanner:
    def __init__(self, client, aggressive=False):
        self.client = client
        self.aggressive = aggressive

    # ---------- XSS ----------
    def _check_xss(self, resp, payload, marker):
        if resp is None or is_error_page(resp):
            return None
        ctype = resp.headers.get("Content-Type", "").lower()
        if "html" not in ctype and "xml" not in ctype:
            return None
        body = resp.text or ""
        if payload not in body:
            return None
        # Reject if escaped variant present (< becomes &lt;)
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped in body and payload not in body:
            return None
        idx = body.find(payload)
        before = body[max(0, idx - 120):idx]

        # Reject if inside HTML comment (not executed)
        if "<!--" in before:
            last_open = before.rfind("<!--")
            last_close = before.rfind("-->")
            if last_open > last_close:
                return None
        # Check if inside <script> block (usually not executed as HTML)
        script_open = body.rfind("<script", 0, idx)
        script_close = body.rfind("</script>", 0, idx)
        inside_script = script_open > script_close
        if inside_script:
            return Finding(
                "MEDIUM", "LOW", "Reflected Payload (inside <script> block)", resp.url,
                "Payload ter-reflect di dalam blok <script> — kemungkinan tidak "
                "langsung executable sebagai HTML, tapi bisa jadi XSS jika "
                "konteks JS-nya longgar.",
                f"Payload: {payload}\nContext: {before[-120:]}",
                "Reflection terjadi di dalam <script> block — perlu verifikasi manual."
            )
        snippet = body[max(0, idx - 80): idx + len(payload) + 80]
        return Finding(
            "HIGH", "CONFIRMED", f"Reflected XSS", resp.url,
            "Payload JavaScript direfleksikan secara LITERAL tanpa encoding di "
            "HTML body → penyerang bisa mencuri cookie/session.",
            f"Payload: {payload}\nSnippet: ...{snippet}...",
            "Payload muncul verbatim (unescaped) di HTML body luar blok <script>."
        )

    # ---------- SQLi: error ----------
    def _check_sqli_error(self, base_resp_body):
        for pat in SQL_ERROR_PATTERNS:
            if re.search(pat, base_resp_body, re.I):
                return pat
        return None

    # ---------- SQLi: time-based 3-tier ----------
    def _median_time(self, url, param, value, samples=2):
        times = []
        for _ in range(samples):
            t0 = time.time()
            r = self.client.get(with_param(url, param, value))
            if r is not None and not is_error_page(r):
                times.append(time.time() - t0)
        if not times:
            return None
        return sorted(times)[len(times) // 2]

    def _time_test(self, url, param, sleep_s):
        t0 = time.time()
        r = self.client.get(with_param(url, param, f"' AND SLEEP({sleep_s})-- -"))
        dt = time.time() - t0
        return (r, dt)

    def test_time_sqli(self, url, param):
        # Baseline
        baseline = self._median_time(url, param, "1", samples=2)
        if baseline is None:
            return None
        results = []
        for sleep_s in SQLI_TIME_PAYLOADS:
            r, dt = self._time_test(url, param, sleep_s)
            if r is None:
                return None
            if is_waf_block(r):
                return None
            results.append((sleep_s, dt))

        # Check correlation: delay should be ≈ sleep for each
        # Allow generous tolerance for network jitter
        confirmed = 0
        for sleep_s, dt in results:
            if dt - baseline >= (sleep_s - 1.2):
                confirmed += 1

        if confirmed >= 3:
            # All 3 sleeps caused delay → CONFIRMED
            return Finding(
                "HIGH", "CONFIRMED", f"SQL Injection (Time-based Blind) — param '{param}'", url,
                "Server tertunda konsisten sebanding dengan SLEEP → blind SQLi.",
                "Baseline: {:.2f}s\n".format(baseline) +
                "\n".join(f"SLEEP({s}) → {d:.2f}s (delta {d-baseline:+.2f})"
                          for s, d in results),
                "3 varian SLEEP (1,3,5 dtk) semuanya menunjukkan penundaan linear "
                "sesuai nilai payload — bukan network jitter."
            )
        elif confirmed >= 2:
            return Finding(
                "HIGH", "MEDIUM", f"SQL Injection (Time-based, partial) — param '{param}'", url,
                "2 dari 3 varian SLEEP menyebabkan penundaan signifikan → suspect.",
                "Baseline: {:.2f}s\n".format(baseline) +
                "\n".join(f"SLEEP({s}) → {d:.2f}s (delta {d-baseline:+.2f})"
                          for s, d in results),
                "Hanya 2 dari 3 yang cocok — bisa false positive dari network jitter."
            )
        return None

    # ---------- Main injection test for a URL (GET or POST) ----------
    def test_param_get(self, base_url, param):
        results = []

        # --- SQLi error ---
        # First check baseline doesn't already contain error pattern
        base_r = self.client.get(base_url)
        if base_r is not None and not is_error_page(base_r):
            base_body = (base_r.text or "")[:200000]
            baseline_error = self._check_sqli_error(base_body)
        else:
            baseline_error = None

        if not baseline_error:
            for payload in SQLI_ERROR_PAYLOADS:
                url = with_param(base_url, param, payload)
                r = self.client.get(url)
                if r is None or is_error_page(r):
                    continue
                if is_waf_block(r):
                    # aggressive: try bypass, else skip
                    if self.aggressive:
                        for variant in tamper_variants(payload)[1:]:
                            url2 = with_param(base_url, param, variant)
                            r2 = self.client.get(url2)
                            if r2 is None or is_error_page(r2) or is_waf_block(r2):
                                continue
                            pat = self._check_sqli_error((r2.text or "")[:400000])
                            if pat:
                                return [Finding(
                                    "HIGH", "CONFIRMED",
                                    f"SQL Injection (Error-based, WAF-bypassed) — param '{param}'",
                                    url2,
                                    "Query SQL tidak disanitasi → eksekusi query arbitrer.",
                                    f"Payload: {variant}\nPola: '{pat}'\n"
                                    f"Baseline (raw): WAF block pada payload asli.\n"
                                    f"Variant berhasil bypass WAF.",
                                    "Error SQL muncul setelah payload di-encode ulang."
                                )]
                    continue
                pat = self._check_sqli_error((r.text or "")[:400000])
                if pat:
                    return [Finding(
                        "HIGH", "CONFIRMED", f"SQL Injection (Error-based) — param '{param}'", url,
                        "Query SQL tidak disanitasi → eksekusi query arbitrer.",
                        f"Payload: {payload}\nPola: '{pat}'\n"
                        f"Body snippet: {self._grab_snippet(r.text, pat)}",
                        "Error SQL muncul verbatim HANYA setelah payload dikirim, "
                        "bukan di baseline."
                    )]

        # --- SQLi boolean ---
        for t, f in SQLI_BOOL_PAIRS:
            rt = self.client.get(with_param(base_url, param, t))
            rf = self.client.get(with_param(base_url, param, f))
            if rt is None or rf is None:
                continue
            if is_error_page(rt) or is_error_page(rf):
                continue
            if is_waf_block(rt) or is_waf_block(rf):
                continue
            lt, lf = len(rt.content), len(rf.content)
            denom = max(lt, lf, 1)
            if denom > 0 and abs(lt - lf) / denom > 0.20:
                return [Finding(
                    "HIGH", "HIGH", f"SQL Injection (Boolean-based) — param '{param}'", base_url,
                    "Response berbeda signifikan antara kondisi TRUE vs FALSE → "
                    "mengindikasikan blind SQLi.",
                    f"TRUE  ({t}): {lt}B\nFALSE ({f}): {lf}B\nDelta: {abs(lt-lf)}B "
                    f"({abs(lt-lf)/denom:.1%})",
                    "Selisih >20% antar dua payload boolean mirror menandakan "
                    "perbedaan query (perlu konfirmasi manual untuk menghindari "
                    "dynamic content false positive)."
                )]

        # --- SQLi time ---
        tf = self.test_time_sqli(base_url, param)
        if tf:
            return [tf]

        # --- XSS ---
        marker = rand_str(10)
        payload = XSS_MARKER_TEMPLATE.format(m=marker)
        xr = self.client.get(with_param(base_url, param, payload))
        if xr is not None and not is_waf_block(xr):
            xf = self._check_xss(xr, payload, marker)
            if xf:
                xf.vtype = xf.vtype + f" — param '{param}'"
                return [xf]

        # --- LFI ---
        for payload in LFI_PAYLOADS:
            url = with_param(base_url, param, payload)
            r = self.client.get(url)
            if r is None or is_error_page(r):
                continue
            if is_waf_block(r):
                continue
            body = (r.text or "")[:200000]
            for ind in LFI_INDICATORS:
                if ind in body:
                    idx = body.find(ind)
                    return [Finding(
                        "CRITICAL", "CONFIRMED", f"Local File Inclusion — param '{param}'", url,
                        "Parameter membaca file lokal server → dapat berujung RCE.",
                        f"Payload: {payload}\nIndikator '{ind}' ditemukan.\n"
                        f"Snippet: {body[max(0,idx-100):idx+200].replace(chr(10),' ')[:300]}",
                        "Isi /etc/passwd atau win.ini cocok verbatim di response."
                    )]

        # --- Open Redirect ---
        if param.lower() in REDIRECT_PARAMS:
            target = "https://evil.pentes.invalid/r"
            r = self.client.get(with_param(base_url, param, target), allow_redirects=False)
            if r is not None and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.pentes.invalid" in loc:
                    return [Finding(
                        "MEDIUM", "CONFIRMED", f"Open Redirect — param '{param}'",
                        with_param(base_url, param, target),
                        "Parameter tidak memvalidasi URL tujuan → phishing, OAuth "
                        "token steal.",
                        f"Payload: {target}\nHTTP {r.status_code} Location: {loc}",
                        "Location header persis mengarah ke domain attacker."
                    )]
        return results

    @staticmethod
    def _grab_snippet(body, pattern):
        m = re.search(pattern, body, re.I)
        if not m:
            return ""
        return body[max(0, m.start() - 60): m.end() + 100].replace("\n", " ").strip()[:250]

    def scan_url(self, url):
        findings = []
        params = extract_params(url)
        for param in params:
            try:
                res = self.test_param_get(url, param)
                for f in res:
                    sp(f.render())
                findings.extend(res)
            except Exception:
                continue
        return findings

    def scan_form(self, form):
        """POST injection test on form."""
        findings = []
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        def send(data):
            if method == "POST":
                return self.client.post(action, data=data)
            else:
                return self.client.get(action, params=data)

        # Baseline
        baseline_data = dict(inputs)
        base_r = send(baseline_data)
        if base_r is None or is_error_page(base_r):
            return findings
        baseline_len = len(base_r.content)
        baseline_body = (base_r.text or "")[:400000]

        # SQL error baseline
        baseline_error = self._check_sqli_error(baseline_body)

        for input_name in inputs.keys():
            # SQL error
            if not baseline_error:
                for payload in SQLI_ERROR_PAYLOADS:
                    data = dict(inputs)
                    data[input_name] = payload
                    r = send(data)
                    if r is None or is_error_page(r):
                        continue
                    if is_waf_block(r):
                        continue
                    pat = self._check_sqli_error((r.text or "")[:400000])
                    if pat:
                        f = Finding(
                            "HIGH", "CONFIRMED",
                            f"SQL Injection (Error-based, POST) — field '{input_name}'",
                            action,
                            "Query SQL tidak disanitasi pada form POST.",
                            f"Form action: {action}\nMethod: {method}\n"
                            f"Field: {input_name}\nPayload: {payload}\n"
                            f"Pola: '{pat}'\nSnippet: {self._grab_snippet(r.text, pat)}",
                            "Error SQL muncul setelah field diisi payload, "
                            "bukan di baseline."
                        )
                        sp(f.render())
                        findings.append(f)
                        break

            # XSS (reflection only — POST XSS hard to confirm executable)
            marker = rand_str(10)
            payload = XSS_MARKER_TEMPLATE.format(m=marker)
            data = dict(inputs)
            data[input_name] = payload
            r = send(data)
            if r is None or is_error_page(r):
                continue
            if is_waf_block(r):
                continue
            xf = self._check_xss(r, payload, marker)
            if xf:
                xf.vtype = xf.vtype + f" (POST field '{input_name}')"
                sp(xf.render())
                findings.append(xf)

        return findings


# ============================================================
# PARAMETER DISCOVERY (ARJUN-STYLE)
# ============================================================
COMMON_PARAMS = [
    # Generic
    "id", "page", "file", "url", "search", "q", "s", "cat", "category",
    "product", "user", "name", "email", "action", "lang", "language",
    "view", "type", "mode", "do", "cmd", "exec", "run",
    "redirect", "return", "next", "target", "dest", "destination",
    "token", "key", "hash", "auth", "session", "sid", "sess",
    "callback", "jsonp", "format", "output",
    "debug", "test", "admin", "config",
    # Path/File
    "path", "filename", "doc", "document", "folder", "dir",
    "include", "require", "template", "theme", "template_name", "page_name",
    # Sort/Filter
    "sort", "order", "orderby", "limit", "offset", "start", "end",
    "filter", "where", "group", "groupby",
    # WordPress
    "author", "p", "page_id", "attachment_id", "tag", "feed",
    "preview", "m", "year", "monthnum", "day", "hour", "minute",
    "second", "pagename", "error", "attachment", "nonce", "action",
    # API
    "api", "api_key", "apikey", "access_token", "client_id", "secret",
    "data", "json", "payload", "body", "content",
    # Misc
    "w", "a", "b", "c", "e", "f", "g", "h", "i", "j", "k", "l", "n", "o",
    "show", "display", "print", "preview", "download", "share", "embed",
]


def discover_params(client, base_url, threads=15, verbose=False):
    """Return set of parameters that the server actually cares about."""
    # Baseline: send a random param with random value
    rnd_param = "pentes_" + rand_str(8)
    rnd_value = rand_str(10)
    baseline_url = add_param(base_url, rnd_param, rnd_value)
    if baseline_url is None:
        baseline_url = base_url + ("&" if "?" in base_url else "?") + f"{rnd_param}={rnd_value}"
    base_resp = client.get(baseline_url)
    if base_resp is None:
        return set(), {}
    base_sig = response_sig(base_resp)
    base_len = len(base_resp.content)

    found = {}
    lock = threading.Lock()

    def test(param):
        marker = "pentes_" + rand_str(10)
        test_url = add_param(base_url, param, marker)
        if test_url is None:
            return None
        r = client.get(test_url)
        if r is None or is_error_page(r):
            return None
        if is_waf_block(r):
            return None
        body = r.text or ""
        # Reflection = highest confidence
        if marker in body:
            with lock:
                found[param] = "reflected"
            return ("reflected", param, test_url)
        # Length/signature change = medium confidence
        sig = response_sig(r)
        if sigs_differ(base_sig, sig):
            with lock:
                found[param] = "differs"
            return ("differs", param, test_url)
        return None

    if verbose:
        sp(f"{C.DIM}[param-discovery] testing {len(COMMON_PARAMS)} parameters...{C.R}")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(test, p) for p in COMMON_PARAMS]
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                continue
            if res:
                how, param, u = res
                if verbose:
                    sp(f"{C.GREEN}[+] Parameter found: {param} ({how}) → {u}{C.R}")
    return set(found.keys()), found


# ============================================================
# WORDPRESS ENUMERATION (AGGRESSIVE)
# ============================================================
def scan_wordpress(client, base_url):
    findings = []
    base = base_url.rstrip("/")

    # 1. User enumeration via REST API
    r = client.get(f"{base}/wp-json/wp/v2/users")
    if r is not None and r.status_code == 200 and not is_error_page(r):
        try:
            users = r.json()
            if isinstance(users, list) and users:
                names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
                names = [n for n in names if n]
                if names:
                    findings.append(Finding(
                        "MEDIUM", "CONFIRMED", "WordPress User Enumeration (REST API)", 
                        f"{base}/wp-json/wp/v2/users",
                        "Endpoint REST API membocorkan daftar user → memudahkan "
                        "brute-force dan social engineering.",
                        f"Users exposed: {', '.join(names[:10])}",
                        "Response JSON berisi array user lengkap dengan slug/name."
                    ))
        except Exception:
            pass

    # 2. xmlrpc.php
    r = client.post(
        f"{base}/xmlrpc.php",
        data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
        headers={"Content-Type": "text/xml"}
    )
    if r is not None and r.status_code == 200 and "methodResponse" in (r.text or ""):
        methods = re.findall(r"<string>([^<]+)</string>", r.text or "")
        findings.append(Finding(
            "MEDIUM", "CONFIRMED", "WordPress XML-RPC Enabled", 
            f"{base}/xmlrpc.php",
            "xmlrpc.php aktif → dapat disalahgunakan untuk brute-force "
            "(system.multicall) dan pingback SSRF.",
            f"Methods exposed: {', '.join(methods[:8])}{'...' if len(methods) > 8 else ''}",
            "Response XML methodResponse valid berisi daftar method."
        ))

    # 3. readme.html → version disclosure
    r = client.get(f"{base}/readme.html")
    if r is not None and r.status_code == 200 and not is_error_page(r):
        m = re.search(r"Version\s+([\d.]+)", r.text or "", re.I)
        if m:
            findings.append(Finding(
                "LOW", "CONFIRMED", "WordPress Version Disclosure", 
                f"{base}/readme.html",
                "Versi WordPress terbuka → memudahkan pencarian CVE spesifik.",
                f"Detected version: {m.group(1)}",
                "readme.html menyebut versi verbatim."
            ))

    # 4. Login page accessible
    r = client.get(f"{base}/wp-login.php")
    if r is not None and r.status_code == 200 and "wp-submit" in (r.text or ""):
        findings.append(Finding(
            "INFO", "CONFIRMED", "WordPress Login Page Accessible",
            f"{base}/wp-login.php",
            "Halaman login WordPress dapat diakses publik (default). Pastikan "
            "rate-limit / captcha aktif.",
            "Form login wp-login.php ditemukan dengan field 'wp-submit'.",
            "Response 200 dengan form login WordPress standar."
        ))

    # 5. Registration open?
    r = client.get(f"{base}/wp-login.php?action=register")
    if r is not None and r.status_code == 200 and "registerform" in (r.text or ""):
        findings.append(Finding(
            "MEDIUM", "CONFIRMED", "WordPress User Registration Open",
            f"{base}/wp-login.php?action=register",
            "Pendaftaran user publik aktif → spam / escalation vector.",
            "Form registrasi ('registerform') tersedia tanpa autentikasi.",
            "Form register tampil di response."
        ))

    # 6. Directory listing on uploads
    r = client.get(f"{base}/wp-content/uploads/")
    if r is not None and r.status_code == 200:
        body = r.text or ""
        if re.search(r"Index of /", body, re.I):
            findings.append(Finding(
                "MEDIUM", "CONFIRMED", "WordPress Uploads Directory Listing",
                f"{base}/wp-content/uploads/",
                "Direktori uploads menampilkan isi → enumerasi file user.",
                "Halaman 'Index of /' menampilkan listing file.",
                "Signature 'Index of /' di uploads dir."
            ))

    # 7. Debug log
    r = client.get(f"{base}/wp-content/debug.log")
    if r is not None and r.status_code == 200 and not is_error_page(r):
        body = r.text or ""
        if len(body.strip()) > 50 and any(x in body.lower() for x in ["php warning", "php notice", "php fatal", "stack trace"]):
            findings.append(Finding(
                "HIGH", "CONFIRMED", "WordPress Debug Log Exposed",
                f"{base}/wp-content/debug.log",
                "debug.log terekspos → berisi path, query, error, potensi "
                "kredensial dari plugin.",
                f"Size: {len(body)}B\nSnippet: {body[:300].replace(chr(10),' ')}",
                "File berisi entry log PHP (warning/notice/fatal) yang valid."
            ))

    # 8. Plugin detection from HTML
    r = client.get(base)
    if r is not None and not is_error_page(r):
        plugins = set(re.findall(r"/wp-content/plugins/([a-z0-9\-_]+)/", r.text or "", re.I))
        themes = set(re.findall(r"/wp-content/themes/([a-z0-9\-_]+)/", r.text or "", re.I))
        if plugins:
            findings.append(Finding(
                "INFO", "CONFIRMED", "WordPress Plugins Detected", base,
                "Plugin terdeteksi di HTML → bisa dicocokkan dengan CVE publik.",
                "Plugins: " + ", ".join(sorted(plugins)[:15]),
                "Path /wp-content/plugins/<name>/ muncul di HTML."
            ))
        if themes:
            findings.append(Finding(
                "INFO", "CONFIRMED", "WordPress Theme Detected", base,
                "Theme terdeteksi di HTML.",
                "Themes: " + ", ".join(sorted(themes)[:5]),
                "Path /wp-content/themes/<name>/ muncul di HTML."
            ))

    return findings


# ============================================================
# GRAPHQL
# ============================================================
def scan_graphql(client, base_url):
    findings = []
    url = f"{base_url.rstrip('/')}/graphql"
    query = {"query": "{__schema{types{name kind fields{name}}}}"}
    r = client.post(url, json=query, headers={"Content-Type": "application/json"})
    if r is None or is_error_page(r):
        return findings
    if r.status_code == 200 and "__schema" in (r.text or ""):
        findings.append(Finding(
            "MEDIUM", "CONFIRMED", "GraphQL Introspection Enabled", url,
            "Introspection aktif → attacker dapat memetakan seluruh schema.",
            f"HTTP {r.status_code}\nSnippet: {(r.text or '')[:200]}",
            "Response 200 dengan 'data' berisi __schema."
        ))
    return findings


# ============================================================
# REPORT
# ============================================================
def get_download_dir():
    for c in [
        "/storage/shared/Download",
        os.path.expanduser("~/storage/shared/Download"),
        os.path.expanduser("~/storage/downloads"),
        os.path.expanduser("~/Downloads"),
        os.getcwd(),
    ]:
        try:
            if os.path.isdir(c) and os.access(c, os.W_OK):
                return c
        except Exception:
            continue
    return os.getcwd()


def safe_filename(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80]


def group_by_severity(findings):
    s = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        s[f.severity] += 1
    return s


def build_txt_report(target, findings, started, finished, mode):
    lines = []
    lines.append("=" * 78)
    lines.append(f"  PENTES v3.0 — WEB VULNERABILITY SCAN REPORT  (mode: {mode})")
    lines.append("=" * 78)
    lines.append(f" Target      : {target}")
    lines.append(f" Start Time  : {started}")
    lines.append(f" Finish Time : {finished}")
    lines.append(f" Total       : {len(findings)} findings")
    lines.append("-" * 78)
    summary = group_by_severity(findings)
    lines.append(" SUMMARY (by severity)")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"   [{s:<8}] {summary[s]}")
    lines.append("-" * 78)
    lines.append(" CONFIDENCE LEGEND")
    lines.append("   CONFIRMED = verified with verbatim evidence")
    lines.append("   HIGH      = strong signal, highly likely true")
    lines.append("   MEDIUM    = moderate signal, manual verification recommended")
    lines.append("   LOW       = weak signal (transparency only, do not act on)")
    lines.append("=" * 78)
    lines.append("")

    ordered = sorted(
        findings,
        key=lambda x: (SEVERITY_ORDER[x.severity], CONF_ORDER[x.confidence]),
        reverse=True,
    )
    for i, f in enumerate(ordered, 1):
        lines.append(f"[{i}] [{f.severity}] [{f.confidence}] {f.vtype}")
        lines.append(f"     URL       : {f.url}")
        lines.append(f"     Impact    : {f.description}")
        if f.reason:
            lines.append(f"     Reason    : {f.reason}")
        if f.evidence:
            for ln in f.evidence.split("\n"):
                lines.append(f"     Evidence  : {ln}")
        lines.append(f"     Timestamp : {f.timestamp}")
        lines.append("-" * 78)
    lines.append("")
    lines.append("Generated by Pentes v3.0 — For authorized testing only.")
    return "\n".join(lines)


def build_html_report(target, findings, started, finished, mode):
    sev_colors = {
        "CRITICAL": "#ff2b2b", "HIGH": "#ff8c1a",
        "MEDIUM": "#ffd400", "LOW": "#2b8cff", "INFO": "#14c8c8",
    }
    conf_colors = {
        "CONFIRMED": "#14c8c8", "HIGH": "#14c8c8",
        "MEDIUM": "#ffd400", "LOW": "#8b949e",
    }
    summary = group_by_severity(findings)
    ordered = sorted(
        findings,
        key=lambda x: (SEVERITY_ORDER[x.severity], CONF_ORDER[x.confidence]),
        reverse=True,
    )
    cards = []
    for f in ordered:
        ev = (f.evidence or "").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        rsn = (f.reason or "").replace("<", "&lt;").replace(">", "&gt;")
        cards.append(f"""
        <div class="card" style="border-left-color:{sev_colors.get(f.severity, '#888')}">
          <div>
            <span class="badge" style="background:{sev_colors.get(f.severity, '#888')}">{f.severity}</span>
            <span class="badge" style="background:{conf_colors.get(f.confidence, '#888')};color:#0d1117">conf: {f.confidence}</span>
          </div>
          <h3>{f.vtype}</h3>
          <p><b>URL:</b> <code>{f.url}</code></p>
          <p><b>Impact:</b> {f.description}</p>
          {f'<p><b>Reason:</b> <em>{rsn}</em></p>' if rsn else ''}
          <p><b>Evidence:</b><br><small>{ev}</small></p>
          <p class="ts">🕒 {f.timestamp}</p>
        </div>""")

    summary_html = "".join(
        f'<div class="sum" style="border-color:{sev_colors[s]}">'
        f'<span style="color:{sev_colors[s]}">{s}</span><br>{summary[s]}</div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Pentes Report - {target}</title>
<style>
  body{{font-family:-apple-system,Consolas,monospace;background:#0d1117;color:#e6edf3;padding:20px;max-width:1000px;margin:auto}}
  h1{{color:#14c8c8}} code{{background:#161b22;padding:2px 6px;border-radius:4px;color:#ffd400;word-break:break-all}}
  .sum{{display:inline-block;text-align:center;padding:12px 20px;margin:6px;border:2px solid #333;border-radius:8px;font-weight:bold}}
  .card{{background:#161b22;border-left:6px solid #333;border-radius:8px;padding:14px;margin:14px 0}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-weight:bold;font-size:12px;margin-right:6px}}
  .ts{{color:#8b949e;font-size:12px}}
  em{{color:#8b949e;font-style:normal;font-size:13px}}
  small{{background:#0d1117;padding:6px;display:block;border-radius:4px;word-break:break-all;white-space:pre-wrap}}
</style></head><body>
<h1>🛡️ Pentes v3.0 — Vulnerability Report</h1>
<p><b>Mode:</b> {mode}<br>
<b>Target:</b> {target}<br><b>Start:</b> {started}<br><b>Finish:</b> {finished}<br>
<b>Total Findings:</b> {len(findings)}</p>
<h2>Summary</h2><div>{summary_html}</div>
<p style="color:#8b949e"><b>Confidence:</b> CONFIRMED = verbatim evidence,
HIGH = strong signal, MEDIUM = verify manually, LOW = weak signal.</p>
<h2>Findings</h2>
{''.join(cards)}
<hr><p style="color:#8b949e;font-size:12px">Generated by Pentes v3.0 — For authorized testing only.</p>
</body></html>"""


def build_json_report(target, findings, started, finished, mode):
    return json.dumps({
        "mode": mode,
        "target": target, "started": started, "finished": finished,
        "total": len(findings),
        "summary": group_by_severity(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2, ensure_ascii=False)


_STARTED_TS = ["-"]
_MODE_G = ["strict"]


def save_report(target, findings, fmt="txt"):
    dl = get_download_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = safe_filename(urlparse(target).netloc or "target")
    ext = fmt
    filename = f"vulnerability_report_{host}_{ts}.{ext}"
    path = os.path.join(dl, filename)
    started = _STARTED_TS[0]
    finished = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode = _MODE_G[0]

    if fmt == "txt":
        content = build_txt_report(target, findings, started, finished, mode)
    elif fmt == "html":
        content = build_html_report(target, findings, started, finished, mode)
    else:
        content = build_json_report(target, findings, started, finished, mode)

    for p in (path, os.path.join(os.getcwd(), filename)):
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
            return p
        except Exception:
            continue
    return "ERROR: cannot write file"


# ============================================================
# BANNER
# ============================================================
def print_banner():
    print(f"""{C.CYAN}{C.B}
  ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗
  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝
  ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗
  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║
  ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
{C.R}{C.DIM}    Accurate Web Vulnerability Scanner v3.0
    Strict + Aggressive  |  Confidence-scored  |  WAF-aware
    For authorized penetration testing only.
{C.R}""")


def divider(char="─", n=66, color=C.GRAY):
    print(f"{color}{char * n}{C.R}")


def prompt_url():
    while True:
        try:
            raw = input(f"\n{C.CYAN}{C.B}➤ Masukkan URL / domain / kata kunci target: {C.R}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Dibatalkan.")
            sys.exit(0)
        if not raw:
            print("[!] Tidak boleh kosong.")
            continue
        return normalize_target(raw)


# ============================================================
# MAIN SCAN
# ============================================================
def run_scan(target, threads=20, timeout=12, delay=0.0,
             skip_dir=False, skip_inject=False,
             aggressive=False, verbose=False,
             headers=None, cookies=None):
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _STARTED_TS[0] = started
    _MODE_G[0] = "aggressive" if aggressive else "strict"

    divider("═", color=C.CYAN)
    print(f"{C.CYAN}{C.B}  TARGET  :{C.R} {target}")
    print(f"{C.CYAN}{C.B}  START   :{C.R} {started}")
    print(f"{C.CYAN}{C.B}  MODE    :{C.R} {_MODE_G[0].upper()}")
    print(f"{C.CYAN}{C.B}  THREADS :{C.R} {threads}  |  TIMEOUT: {timeout}s  |  DELAY: {delay}s")
    divider("═", color=C.CYAN)

    client = HTTPClient(timeout=timeout, delay=delay,
                        headers=headers, cookies=cookies, verbose=verbose)
    findings = []

    # ---- Preflight ----
    print(f"\n{C.YELLOW}[*] Preflight: verifikasi koneksi...{C.R}")
    probe = client.get(target)
    if probe is None:
        print(f"{C.RED}[!] Target tidak bisa dijangkau (DNS fail / timeout / refused).{C.R}")
        return findings, started

    is_err = is_error_page(probe)
    waf = detect_waf(probe)
    print(f"{C.GREEN}[+] Reachable — HTTP {probe.status_code}  ({len(probe.content)} bytes)")
    if waf:
        print(f"{C.CYAN}[i] WAF terdeteksi: {waf}{C.R}")
    if is_err:
        print(f"{C.YELLOW}[!] Root URL mengembalikan halaman ERROR (origin down / WAF).\n"
              f"    Audit header & fingerprint akan DI-SKIP.{C.R}")

    root = get_root(target)

    # ---- 1. Fingerprint ----
    print(f"\n{C.MAGENTA}{C.B}[1/10] FINGERPRINT & WAF{D.C.R if False else C.R}")
    divider()
    fp = scan_fingerprint(client, target)
    for f in fp: print(f.render())
    findings.extend(fp)

    # ---- 2. Security headers ----
    print(f"\n{C.MAGENTA}{C.B}[2/10] SECURITY HEADERS & COOKIE FLAGS{C.R}")
    divider()
    hdr = scan_security_headers(client, target)
    for f in hdr: print(f.render())
    findings.extend(hdr)

    # ---- 3. CORS ----
    print(f"\n{C.MAGENTA}{C.B}[3/10] CORS{C.R}")
    divider()
    cors = scan_cors(client, target)
    for f in cors: print(f.render())
    findings.extend(cors)
    if not cors: print(f"{C.DIM}    (no CORS issue){C.R}")

    # ---- 4. HTTP Methods ----
    print(f"\n{C.MAGENTA}{C.B}[4/10] HTTP METHODS{C.R}")
    divider()
    meth = scan_methods(client, target)
    for f in meth: print(f.render())
    findings.extend(meth)
    if not meth: print(f"{C.DIM}    (no risky method){C.R}")

    # ---- 5. Directory ----
    if not skip_dir:
        print(f"\n{C.MAGENTA}{C.B}[5/10] DIRECTORY & SENSITIVE FILES{C.R}")
        divider()
        ds = DirScanner(client, root, threads=threads, aggressive=aggressive)
        if ds.soft404:
            print(f"{C.YELLOW}[i] Soft-404 terdeteksi — validasi konten per-file aktif.{C.R}")
        print(f"{C.DIM}[*] Memindai {len(SENSITIVE_PATHS)+len(BINARY_SIGS)} path esensial "
              f"dengan {threads} worker...{C.R}")
        dir_f = ds.run()
        findings.extend(dir_f)
        print(f"{C.GREEN}[+] Directory selesai: {len(dir_f)} temuan.{C.R}")

        # Aggressive: backup file discovery
        if aggressive:
            known = [f.vtype.split(":")[-1].strip().lstrip("/")
                     for f in dir_f if "Exposed" in f.vtype and "Protected" not in f.vtype]
            known = [k for k in known if k and not k.endswith("/")]
            if known:
                print(f"\n{C.DIM}[*] Cek file backup untuk {len(known)} file ditemukan...{C.R}")
                bf = scan_backup_files(client, root, known, threads=threads)
                findings.extend(bf)
                print(f"{C.GREEN}[+] Backup scan: {len(bf)} temuan.{C.R}")

        # Dir listing & debug (both modes)
        dl = scan_directory_listing(client, root)
        for f in dl: print(f.render())
        findings.extend(dl)

        dbg = scan_debug_disclosure(client, root)
        for f in dbg: print(f.render())
        findings.extend(dbg)
    else:
        print(f"\n{C.DIM}[5/10] Skipped (--no-dir).{C.R}")

    # ---- 6. Robots/sitemap harvest + crawl (aggressive) ----
    param_urls = set()
    crawl_urls = [target]
    if aggressive:
        print(f"\n{C.MAGENTA}{C.B}[6/10] CRAWL & PARAMETER DISCOVERY (aggressive){C.R}")
        divider()
        # Harvest robots/sitemap
        harvested = harvest_robots_sitemap(client, root)
        if harvested:
            print(f"{C.DIM}[*] robots/sitemap: {len(harvested)} path ditemukan{C.R}")
        # Recursive crawl
        print(f"{C.DIM}[*] Recursive crawl depth 3, max 50 URLs...{C.R}")
        crawl_urls = crawl_recursive(client, target, max_depth=3, max_urls=50, verbose=verbose)
        print(f"{C.GREEN}[+] Crawled: {len(crawl_urls)} URL unik{C.R}")

        # Extract param URLs from crawl
        param_urls = extract_param_urls_from(crawl_urls)
        print(f"{C.GREEN}[+] URLs dengan parameter existing: {len(param_urls)}{C.R}")

        # Parameter discovery on base URL
        print(f"{C.DIM}[*] Parameter discovery (Arjun-style, {len(COMMON_PARAMS)} kandidat)...{C.R}")
        disc_params, detail = discover_params(client, target, threads=threads, verbose=verbose)
        if disc_params:
            print(f"{C.GREEN}[+] Parameter terdeteksi di base URL: "
                  f"{', '.join(sorted(disc_params))}{C.R}")
            # Add as synthetic param URLs to test
            for p in disc_params:
                marker = "pentes_test"
                u = add_param(target, p, marker)
                if u:
                    param_urls.add(u)
    else:
        print(f"\n{C.DIM}[6/10] Skipped crawl/param-discovery (--aggressive untuk aktifkan).{C.R}")
        if "?" in target and extract_params(target):
            param_urls.add(target)

    # ---- 7. Injection (GET) ----
    if not skip_inject:
        print(f"\n{C.MAGENTA}{C.B}[7/10] INJECTION TESTS (GET){C.R}")
        divider()
        if not param_urls:
            print(f"{C.DIM}    Tidak ada parameter GET untuk diuji.\n"
                  f"    Gunakan --aggressive untuk auto-discovery parameter.{C.R}")
        else:
            print(f"{C.DIM}[*] Menguji {len(param_urls)} URL berparameter...{C.R}")
            inj = InjectionScanner(client, aggressive=aggressive)
            for u in param_urls:
                print(f"{C.DIM}    → {u}{C.R}")
                inj_f = inj.scan_url(u)
                findings.extend(inj_f)
    else:
        print(f"\n{C.DIM}[7/10] Skipped (--no-inject).{C.R}")

    # ---- 8. Form POST testing (aggressive) ----
    if aggressive and not skip_inject:
        print(f"\n{C.MAGENTA}{C.B}[8/10] FORM EXTRACTION & POST INJECTION (aggressive){C.R}")
        divider()
        all_forms = []
        pages_to_scan = crawl_urls[:25]
        for u in pages_to_scan:
            forms = extract_forms(client, u)
            all_forms.extend(forms)
        # Dedupe by (action, method, tuple of input names)
        seen = set()
        unique = []
        for f in all_forms:
            k = (f["action"], f["method"], tuple(sorted(f["inputs"].keys())))
            if k in seen:
                continue
            seen.add(k)
            unique.append(f)
        print(f"{C.GREEN}[+] Forms ditemukan: {len(unique)}{C.R}")
        inj = InjectionScanner(client, aggressive=aggressive)
        for f in unique:
            print(f"{C.DIM}    → {f['method']} {f['action']} "
                  f"({len(f['inputs'])} fields){C.R}")
            try:
                findings.extend(inj.scan_form(f))
            except Exception:
                continue
    else:
        print(f"\n{C.DIM}[8/10] Skipped form POST (--aggressive untuk aktifkan).{C.R}")

    # ---- 9. WordPress (aggressive) ----
    if aggressive:
        print(f"\n{C.MAGENTA}{C.B}[9/10] WORDPRESS ENUMERATION (aggressive){C.R}")
        divider()
        # Check if WP
        r = client.get(target)
        is_wp = r is not None and ("/wp-content/" in (r.text or "") or "/wp-includes/" in (r.text or ""))
        if is_wp:
            print(f"{C.GREEN}[+] WordPress terdeteksi — menjalankan enumerasi...{C.R}")
            wp = scan_wordpress(client, root)
            for f in wp: print(f.render())
            findings.extend(wp)
        else:
            print(f"{C.DIM}    (bukan WordPress atau tidak terdeteksi){C.R}")
    else:
        print(f"\n{C.DIM}[9/10] Skipped WordPress enum (--aggressive).{C.R}")

    # ---- 10. GraphQL ----
    print(f"\n{C.MAGENTA}{C.B}[10/10] GRAPHQL INTROSPECTION{C.R}")
    divider()
    gql = scan_graphql(client, root)
    for f in gql: print(f.render())
    findings.extend(gql)
    if not gql: print(f"{C.DIM}    (no GraphQL detected){C.R}")

    finished = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---- SUMMARY ----
    print()
    divider("═", color=C.CYAN)
    print(f"{C.CYAN}{C.B}  SCAN COMPLETE  |  {finished}{C.R}")
    divider("═", color=C.CYAN)
    summary = group_by_severity(findings)
    print(f"{C.B}  TOTAL FINDINGS: {len(findings)}{C.R}")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"  {SEVERITY_COLOR[s]}[{s:<8}]{C.R} : {summary[s]}")

    conf = {"CONFIRMED": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        conf[f.confidence] = conf.get(f.confidence, 0) + 1
    print(f"{C.B}  CONFIDENCE:{C.R} " + "  ".join(
        f"{CONF_COLOR[k]}={v}" for k, v in conf.items() if v
    ))
    divider("═", color=C.CYAN)

    return findings, started


def interactive_save(findings, target):
    try:
        ans = input(f"\n{C.YELLOW}{C.B}Apakah Anda ingin menyimpan laporan pemindaian ini? (y/n): {C.R}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = "n"

    if ans == "y":
        try:
            fmt = input(f"{C.CYAN}Pilih format [txt/html/json] (default: html): {C.R}").strip().lower() or "html"
        except (KeyboardInterrupt, EOFError):
            fmt = "html"
        if fmt not in ("txt", "html", "json"):
            fmt = "html"
        print(f"{C.DIM}[*] Menyimpan laporan...{C.R}")
        path = save_report(target, findings, fmt=fmt)
        if path.startswith("ERROR"):
            print(f"{C.RED}[!] Gagal menyimpan: {path}{C.R}")
        else:
            print(f"{C.GREEN}{C.B}[✓] Tersimpan:{C.R}\n{C.GREEN}    {path}{C.R}")
    else:
        print(f"{C.BLUE}[i] Tidak disimpan. Findings dikosongkan.{C.R}")
        findings.clear()


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        prog="pentes",
        description="Pentes v3.0 — Accurate Web Vulnerability Scanner (Termux)",
    )
    parser.add_argument("target", nargs="?", help="URL / domain / keyword")
    parser.add_argument("--threads", type=int, default=20, help="Worker (default 20)")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout (default 12)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay per request (s)")
    parser.add_argument("--no-dir", action="store_true", help="Skip directory scan")
    parser.add_argument("--no-inject", action="store_true", help="Skip injection tests")
    parser.add_argument("--aggressive", action="store_true",
                        help="Aktifkan param discovery, crawl, POST, WP enum, backup scan")
    parser.add_argument("--verbose", action="store_true",
                        help="Tampilkan setiap request & response")
    parser.add_argument("--header", action="append", default=[],
                        help="Custom header 'Name: Value' (repeatable)")
    parser.add_argument("--cookie", type=str, default=None,
                        help="Custom cookie string")
    args = parser.parse_args()

    print_banner()

    target = normalize_target(args.target) if args.target else prompt_url()

    try:
        findings, _ = run_scan(
            target,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            skip_dir=args.no_dir,
            skip_inject=args.no_inject,
            aggressive=args.aggressive,
            verbose=args.verbose,
            headers=args.header,
            cookies=args.cookie,
        )
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Scan dibatalkan.{C.R}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{C.RED}[!] Fatal error: {e}{C.R}")
        traceback.print_exc()
        sys.exit(1)

    interactive_save(findings, target)
    print(f"\n{C.GREEN}{C.B}[✓] Selesai. Stay ethical.{C.R}\n")


if __name__ == "__main__":
    main()
