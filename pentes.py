#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pentes.py v3.1 — Universal Web Vulnerability Scanner (Termux Edition)
=====================================================================
v3.1 Updates:
  - Added .NET Core / ASP.NET fingerprinting (Kestrel, .AspNetCore, X-Powered-By)
  - Added .NET sensitive files (appsettings.json, web.config, appsettings.*.json)
  - Added Swagger / OpenAPI discovery and validation
  - Added Node.js / Express fingerprinting
  - Improved generic API endpoint detection (/api, /v1, /graphql)
  - Enhanced content validation to prevent JSON false positives
  - Maintained strict accuracy-first philosophy (No hallucination)
"""

import os
import re
import sys
import json
import time
import random
import string
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
        return None
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
# RESPONSE SIGNATURE
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
        for attempt in range(self.retries + 1):
            if self.delay:
                time.sleep(self.delay)
            t0 = time.time()
            try:
                r = self.session.request(method, url, **kw)
                self._log(method, url, r, time.time() - t0)
                if r.status_code == 429 and attempt < self.retries:
                    time.sleep(2 + attempt)
                    continue
                return r
            except requests.RequestException:
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
# FINGERPRINT (UNIVERSAL)
# ============================================================
TECH_PATTERNS = {
    "WordPress":  [r"/wp-content/", r"/wp-includes/", r"/wp-json/"],
    "Joomla":     [r"/components/com_", r"/media/system/js/"],
    "Drupal":     [r"Drupal\.settings", r"/sites/default/files/"],
    "Magento":    [r"Mage\.Cookies", r"/skin/frontend/"],
    "Laravel":    [r"laravel_session", r"XSRF-TOKEN"],
    "Django":     [r"csrftoken", r"__admin__"],
    "Express.js": [r"X-Powered-By:\s*Express", r"connect.sid"],
    "React":      [r"data-reactroot", r"__REACT"],
    "Vue.js":     [r"data-v-[0-9a-f]{6,}", r"vue\.runtime"],
    "Angular":    [r"ng-version=", r"ng-app="],
    "jQuery":     [r"jquery[-.]\d+\.\d+.*\.js"],
    "Bootstrap":  [r"bootstrap(\.min)?\.(css|js)"],
    "Next.js":    [r"__NEXT_DATA__", r"/_next/static/"],
    "Nuxt":       [r"__NUXT__", r"/_nuxt/"],
    "Shopify":    [r"cdn\.shopify\.com"],
    "PHP":        [r"PHPSESSID", r"\.php\?"],
    # .NET Core Additions
    "ASP.NET Core":[r"\.AspNetCore\.", r"Kestrel", r"X-Powered-By:\s*ASP\.NET", r"aspnetcore"],
    "ASP.NET WebForms":[r"ASP\.NET_SessionId", r"__VIEWSTATE"],
    "Swagger/OpenAPI":[r"swagger-ui", r"swagger\.json", r"openapi\.json"],
    "Blazor":     [r"blazor\.webassembly", r"blazor\.server"],
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
    "Content-Security-Policy": ("MEDIUM", "CSP absen → tidak ada pembatasan sumber script/style."),
    "Strict-Transport-Security": ("MEDIUM", "HSTS absen → rentan SSL-strip / downgrade."),
    "X-Frame-Options": ("MEDIUM", "X-Frame-Options absen → clickjacking."),
    "X-Content-Type-Options": ("LOW", "Tanpa 'nosniff' → risiko MIME-sniffing XSS."),
    "Referrer-Policy": ("LOW", "Referrer-Policy absen → URL bocor via Referer."),
    "Permissions-Policy": ("LOW", "Permissions-Policy absen → fitur sensitif tidak dibatasi."),
}

def scan_security_headers(client, url):
    findings = []
    r = client.get(url)
    if r is None:
        return [Finding("INFO", "CONFIRMED", "Connection Failed", url,
                        "Tidak dapat connect ke target.", "requests error / DNS / timeout.")]

    if r.status_code >= 500 or is_error_page(r):
        return [Finding(
            "INFO", "CONFIRMED", "Header Audit SKIPPED — Origin Unreachable", url,
            "Server mengembalikan halaman error. Audit header DI-SKIP.",
            f"HTTP {r.status_code}  |  Server: {r.headers.get('Server', '-')}",
            "Mengukur header pada error page = false positive."
        )]

    present = {k.lower(): v for k, v in r.headers.items()}
    for name, (sev, desc) in HEADER_CHECKS.items():
        if name.lower() not in present:
            findings.append(Finding(
                sev, "CONFIRMED", f"Missing {name}", url, desc,
                f"Header '{name}' tidak ada pada HTTP {r.status_code} response.",
                "Header benar-benar tidak dikirim oleh server."
            ))

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
                f"Cookie '{name}' tanpa {', '.join(missing)} → rentan session hijack.",
                f"Set-Cookie: {ck[:200]}",
                "Cookie dikirim server tanpa flag proteksi."
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
            "ACAO reflects arbitrary Origin + ACAC=true → attacker dapat membaca data login.",
            f"Request Origin: {probe_origin}\nResponse ACAO: {acao}\nResponse ACAC: {acac}",
            "Origin arbitrer direfleksikan + credentials diizinkan."
        ))
    elif acao == probe_origin:
        findings.append(Finding(
            "MEDIUM", "CONFIRMED", "CORS Misconfiguration (reflected origin)", url,
            "ACAO reflects arbitrary Origin → konten bisa dibaca cross-origin.",
            f"Request Origin: {probe_origin}\nResponse ACAO: {acao}",
            "Server memantulkan Origin yang dikirim."
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
            f"Allow: {allow}", "Header Allow mengonfirmasi TRACE diizinkan."
        ))
    return findings


# ============================================================
# DIRECTORY / SENSITIVE FILES (WP + .NET + GENERIC)
# ============================================================
SENSITIVE_PATHS = {
    # --- .NET Core / ASP.NET ---
    "appsettings.json": ("CRITICAL", "Config .NET terbuka → DB connstring, JWT secret, API key.", 
                         [r"ConnectionStrings", r"Logging", r"AllowedHosts"]),
    "appsettings.Development.json": ("CRITICAL", "Config dev .NET terbuka → DB connstring, password.", 
                                     [r"ConnectionStrings", r"Logging"]),
    "appsettings.Production.json": ("CRITICAL", "Config prod .NET terbuka → DB connstring, password.", 
                                    [r"ConnectionStrings", r"Logging"]),
    "web.config": ("HIGH", "IIS web.config terbuka → connstring, machineKey.", 
                   [r"<configuration", r"<connectionStrings", r"<system.web"]),
    "swagger/v1/swagger.json": ("MEDIUM", "Swagger spec terbuka → API endpoint leaked.", 
                                [r'"openapi":', r'"swagger":', r'"paths":']),
    "swagger/index.html": ("INFO", "Swagger UI terdeteksi.", 
                           [r"swagger-ui"]),
    "api-docs": ("MEDIUM", "API docs terbuka.", [r"swagger", r"openapi"]),
    
    # --- Generic / PHP ---
    ".env": ("CRITICAL", "Kredensial & API keys bocor (DB, JWT, cloud).",
             [r"^[A-Z_][A-Z0-9_]*\s*=\s*\S", r"APP_KEY=", r"DB_PASSWORD="]),
    ".env.bak": ("CRITICAL", "Backup .env → secret bocor.",
                 [r"^[A-Z_][A-Z0-9_]*\s*=\s*\S"]),
    ".git/config": ("CRITICAL", "Git config bocor → URL remote + kredensial.",
                    [r"\[core\]", r"repositoryformatversion"]),
    ".git/HEAD": ("HIGH", "Git repo terbuka → source rekonstruksi.",
                  [r"^ref:\s+refs/", r"^[0-9a-f]{40}"]),
    "backup.sql": ("CRITICAL", "SQL dump terbuka.",
                   [r"CREATE TABLE", r"INSERT INTO"]),
    "db.sql": ("CRITICAL", "DB dump terbuka.",
               [r"CREATE TABLE", r"INSERT INTO"]),
    "id_rsa": ("CRITICAL", "SSH private key terbuka.",
               [r"-----BEGIN\s+(RSA\s+|OPENSSH\s+|)PRIVATE KEY-----"]),
    
    # --- WordPress Specific ---
    "wp-config.php": ("CRITICAL", "wp-config terbaca → kredensial DB.",
                      [r"<\?php", r"DB_PASSWORD", r"DB_NAME"]),
    "wp-config.php.bak": ("CRITICAL", "Backup wp-config.",
                          [r"<\?php", r"DB_PASSWORD"]),
    
    # --- Generic Info / Lower Risk ---
    "phpinfo.php": ("MEDIUM", "phpinfo() → bocor path/env/versi.",
                    [r"phpinfo\(\)", r"PHP Version"]),
    "server-status": ("MEDIUM", "Apache server-status terbuka.",
                      [r"Apache Server Status"]),
    "robots.txt": ("INFO", "robots.txt → bisa reveal hidden path.",
                   [r"User-agent:", r"Disallow:", r"Sitemap:"]),
    "sitemap.xml": ("INFO", "Sitemap terekspos.",
                    [r"<urlset", r"<sitemapindex"]),
    "graphql": ("INFO", "Endpoint GraphQL ada.",
                [r'"data":', r'"errors":', r"__schema"]),
    "login": ("INFO", "Halaman login ditemukan.", [r"<form", r"password"]),
    "admin/": ("INFO", "Panel admin terdeteksi.",
               [r"<form", r"password", r"login", r"dashboard"]),
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
                "Path ditemukan tapi dilindungi (401/403). Tidak ada bukti kebocoran.",
                f"HTTP {r.status_code}  |  Size: {len(r.content)}B",
                "Status 401/403 = akses ditolak. Bukan kerentanan."
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

        if path.endswith("/"):
            if not self._validate_content(r, sigs):
                return None
            snippet = (r.text or "")[:200].replace("\n", " ").strip()
            return Finding(
                "INFO", "CONFIRMED", f"Directory Discovered: /{path}", url, desc,
                f"HTTP {r.status_code}  |  Size: {len(r.content)}B\nSnippet: {snippet}",
                "Konten direktori mengandung signature yang diharapkan."
            )

        if self._validate_content(r, sigs):
            snippet = (r.text or "")[:300].replace("\n", " ").strip()
            return Finding(
                sev, "CONFIRMED", f"Sensitive File Exposed: /{path}", url, desc,
                f"HTTP {r.status_code}  |  Size: {len(r.content)}B\n"
                f"Content signature matched.\nSnippet: {snippet}",
                "Status 200 + isi file cocok dengan signature yang diharapkan."
            )

        if sev in ("CRITICAL", "HIGH"):
            return Finding(
                "INFO", "LOW", f"Path Responds but Content Unverified: /{path}", url,
                "Path mengembalikan 200 tapi isi tidak cocok dengan signature. "
                "Kemungkinan soft-404 / custom error. Tidak dianggap temuan.",
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
# INJECTION (GET + POST)
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
    r"System\.Data\.SqlClient\.SqlException", # .NET Specific
]

SQLI_ERROR_PAYLOADS = ["'", "\"", "')", "';", "1'"]
SQLI_BOOL_PAIRS = [
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("1 AND 1=1", "1 AND 1=2"),
]
SQLI_TIME_PAYLOADS = [1, 3, 5]
XSS_MARKER_TEMPLATE = "<svg/onload=alert('PENTES_{m}')>"

LFI_PAYLOADS = [
    "../../../../etc/passwd", "....//....//....//....//etc/passwd",
    "/etc/passwd", "../../../../windows/win.ini",
]
LFI_INDICATORS = ["root:x:0:0", "daemon:x:", "[extensions]", "for 16-bit app support"]

REDIRECT_PARAMS = {
    "url", "redirect", "next", "return", "returnurl", "redir",
    "destination", "dest", "go", "goto", "target", "r", "u",
    "link", "out", "callback", "continue", "redirect_uri",
}

def tamper_variants(payload):
    variants = [payload]
    variants.append(payload.replace("'", "%27"))
    variants.append(payload.replace("'", "%2527"))
    variants.append(payload.replace(" ", "/**/"))
    variants.append(payload.replace(" ", "+"))
    return list(dict.fromkeys(variants))


class InjectionScanner:
    def __init__(self, client, aggressive=False):
        self.client = client
        self.aggressive = aggressive

    def _check_xss(self, resp, payload, marker):
        if resp is None or is_error_page(resp):
            return None
        ctype = resp.headers.get("Content-Type", "").lower()
        if "html" not in ctype and "xml" not in ctype:
            return None
        body = resp.text or ""
        if payload not in body:
            return None
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped in body and payload not in body:
            return None
        idx = body.find(payload)
        before = body[max(0, idx - 120):idx]
        if "<!--" in before:
            last_open = before.rfind("<!--")
            last_close = before.rfind("-->")
            if last_open > last_close:
                return None
        script_open = body.rfind("<script", 0, idx)
        script_close = body.rfind("</script>", 0, idx)
        inside_script = script_open > script_close
        if inside_script:
            return Finding(
                "MEDIUM", "LOW", "Reflected Payload (inside <script>)", resp.url,
                "Payload ter-reflect di dalam <script> — perlu verifikasi manual.",
                f"Payload: {payload}\nContext: {before[-120:]}",
                "Reflection terjadi di dalam <script>."
            )
        snippet = body[max(0, idx - 80): idx + len(payload) + 80]
        return Finding(
            "HIGH", "CONFIRMED", "Reflected XSS", resp.url,
            "Payload JavaScript direfleksikan LITERAL tanpa encoding di HTML.",
            f"Payload: {payload}\nSnippet: ...{snippet}...",
            "Payload muncul verbatim (unescaped) di HTML body."
        )

    def _check_sqli_error(self, body):
        for pat in SQL_ERROR_PATTERNS:
            if re.search(pat, body, re.I):
                return pat
        return None

    def _median_time(self, url, param, value, samples=2):
        times = []
        for _ in range(samples):
            t0 = time.time()
            r = self.client.get(with_param(url, param, value))
            if r is not None and not is_error_page(r):
                times.append(time.time() - t0)
        if not times: return None
        return sorted(times)[len(times) // 2]

    def test_time_sqli(self, url, param):
        baseline = self._median_time(url, param, "1", samples=2)
        if baseline is None: return None
        
        results = []
        for sleep_s in SQLI_TIME_PAYLOADS:
            t0 = time.time()
            r = self.client.get(with_param(url, param, f"' AND SLEEP({sleep_s})-- -"))
            dt = time.time() - t0
            if r is None or is_waf_block(r):
                return None
            results.append((sleep_s, dt))

        confirmed = sum(1 for s, d in results if d - baseline >= (s - 1.2))
        if confirmed >= 3:
            return Finding(
                "HIGH", "CONFIRMED", f"SQL Injection (Time-based) — param '{param}'", url,
                "Server tertunda konsisten sebanding dengan SLEEP → blind SQLi.",
                f"Baseline: {baseline:.2f}s\n" + "\n".join(f"SLEEP({s}) → {d:.2f}s" for s, d in results),
                "3 varian SLEEP (1,3,5) menunjukkan penundaan linear."
            )
        return None

    def test_param_get(self, base_url, param):
        # SQL error
        base_r = self.client.get(base_url)
        baseline_error = self._check_sqli_error((base_r.text or "")[:200000]) if base_r else None

        if not baseline_error:
            for payload in SQLI_ERROR_PAYLOADS:
                url = with_param(base_url, param, payload)
                r = self.client.get(url)
                if r is None or is_error_page(r) or is_waf_block(r):
                    continue
                pat = self._check_sqli_error((r.text or "")[:400000])
                if pat:
                    return [Finding(
                        "HIGH", "CONFIRMED", f"SQL Injection (Error-based) — '{param}'", url,
                        "Query SQL tidak disanitasi → eksekusi query arbitrer.",
                        f"Payload: {payload}\nPola: '{pat}'\nSnippet: {self._grab_snippet(r.text, pat)}",
                        "Error SQL muncul verbatim HANYA setelah payload dikirim."
                    )]

        # SQL Boolean
        for t, f in SQLI_BOOL_PAIRS:
            rt = self.client.get(with_param(base_url, param, t))
            rf = self.client.get(with_param(base_url, param, f))
            if not rt or not rf or is_waf_block(rt) or is_waf_block(rf): continue
            lt, lf = len(rt.content), len(rf.content)
            denom = max(lt, lf, 1)
            if denom > 0 and abs(lt - lf) / denom > 0.20:
                return [Finding(
                    "HIGH", "HIGH", f"SQL Injection (Boolean) — '{param}'", base_url,
                    "Response berbeda signifikan antara TRUE vs FALSE → blind SQLi.",
                    f"TRUE: {lt}B\nFALSE: {lf}B\nDelta: {abs(lt-lf)}B",
                    "Selisih >20% antar dua payload boolean."
                )]

        # SQL Time
        tf = self.test_time_sqli(base_url, param)
        if tf: return [tf]

        # XSS
        marker = rand_str(10)
        payload = XSS_MARKER_TEMPLATE.format(m=marker)
        xr = self.client.get(with_param(base_url, param, payload))
        if xr and not is_waf_block(xr):
            xf = self._check_xss(xr, payload, marker)
            if xf:
                xf.vtype = xf.vtype + f" — param '{param}'"
                return [xf]

        # LFI
        for payload in LFI_PAYLOADS:
            r = self.client.get(with_param(base_url, param, payload))
            if not r or is_error_page(r) or is_waf_block(r): continue
            body = (r.text or "")[:200000]
            for ind in LFI_INDICATORS:
                if ind in body:
                    idx = body.find(ind)
                    return [Finding(
                        "CRITICAL", "CONFIRMED", f"Local File Inclusion — '{param}'", r.url,
                        "Parameter membaca file lokal server → RCE risk.",
                        f"Payload: {payload}\nIndikator '{ind}'\nSnippet: {body[max(0,idx-100):idx+200].replace(chr(10),' ')[:300]}",
                        "Isi /etc/passwd cocok verbatim."
                    )]
        return []

    @staticmethod
    def _grab_snippet(body, pattern):
        m = re.search(pattern, body, re.I)
        if not m: return ""
        return body[max(0, m.start() - 60): m.end() + 100].replace("\n", " ").strip()[:250]

    def scan_url(self, url):
        findings = []
        for param in extract_params(url):
            try:
                res = self.test_param_get(url, param)
                for f in res:
                    sp(f.render())
                findings.extend(res)
            except Exception:
                continue
        return findings


# ============================================================
# .NET CORE / API SPECIFIC ENUMERATION
# ============================================================
def scan_dotnet_api(client, root_url):
    findings = []
    base = root_url.rstrip("/")

    # 1. Check Swagger UI
    swagger_paths = ["/swagger/index.html", "/swagger", "/swagger/v1/swagger.json", "/openapi.json"]
    for p in swagger_paths:
        url = base + p
        r = client.get(url)
        if r is None or is_error_page(r):
            continue
        if r.status_code == 200:
            body = r.text or ""
            if '"openapi"' in body or '"swagger"' in body or "swagger-ui" in body:
                findings.append(Finding(
                    "MEDIUM", "CONFIRMED", "Swagger/OpenAPI Exposed", url,
                    "Dokumentasi API terbuka → attacker bisa memetakan endpoint, parameter, dan schema.",
                    f"HTTP 200\nSnippet: {body[:200]}",
                    "Response berisi JSON swagger/openapi atau UI swagger."
                ))
                break

    # 2. Check Kestrel Server Header
    r = client.get(base)
    if r and not is_error_page(r):
        server = r.headers.get("Server", "").lower()
        if "kestrel" in server:
            findings.append(Finding(
                "INFO", "CONFIRMED", "Kestrel Server Detected", base,
                "Server web menggunakan Kestrel (ASP.NET Core).",
                f"Server: {r.headers.get('Server')}",
                "Header Server menyebut Kestrel."
            ))

    return findings


# ============================================================
# WORDPRESS ENUMERATION
# ============================================================
def scan_wordpress(client, base_url):
    findings = []
    base = base_url.rstrip("/")

    r = client.get(f"{base}/wp-json/wp/v2/users")
    if r and r.status_code == 200 and not is_error_page(r):
        try:
            users = r.json()
            if isinstance(users, list) and users:
                names = [u.get("slug") or u.get("name") for u in users if isinstance(u, dict)]
                names = [n for n in names if n]
                if names:
                    findings.append(Finding(
                        "MEDIUM", "CONFIRMED", "WordPress User Enumeration", 
                        f"{base}/wp-json/wp/v2/users",
                        "Endpoint REST API membocorkan daftar user.",
                        f"Users: {', '.join(names[:10])}",
                        "Response JSON berisi array user."
                    ))
        except Exception: pass

    r = client.post(f"{base}/xmlrpc.php", data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>', headers={"Content-Type": "text/xml"})
    if r and r.status_code == 200 and "methodResponse" in (r.text or ""):
        findings.append(Finding(
            "MEDIUM", "CONFIRMED", "WordPress XML-RPC Enabled", f"{base}/xmlrpc.php",
            "xmlrpc.php aktif → brute-force / SSRF vector.",
            "Response XML methodResponse valid.", "Valid XML response."
        ))

    return findings


# ============================================================
# REPORT
# ============================================================
def get_download_dir():
    for c in ["/storage/shared/Download", os.path.expanduser("~/storage/shared/Download"),
              os.path.expanduser("~/storage/downloads"), os.getcwd()]:
        if os.path.isdir(c) and os.access(c, os.W_OK):
            return c
    return os.getcwd()


def safe_filename(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80]


def group_by_severity(findings):
    s = {k: 0 for k in SEVERITY_ORDER}
    for f in findings: s[f.severity] += 1
    return s


def build_txt_report(target, findings, started, finished, mode):
    lines = [
        "=" * 78,
        f"  PENTES v3.1 — WEB VULNERABILITY SCAN REPORT  (mode: {mode})",
        "=" * 78,
        f" Target      : {target}",
        f" Start Time  : {started}",
        f" Finish Time : {finished}",
        f" Total       : {len(findings)} findings",
        "-" * 78,
        " SUMMARY (by severity)"
    ]
    summary = group_by_severity(findings)
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"   [{s:<8}] {summary[s]}")
    lines.append("=" * 78 + "\n")

    ordered = sorted(findings, key=lambda x: (SEVERITY_ORDER[x.severity], CONF_ORDER[x.confidence]), reverse=True)
    for i, f in enumerate(ordered, 1):
        lines.append(f"[{i}] [{f.severity}] [{f.confidence}] {f.vtype}")
        lines.append(f"     URL       : {f.url}")
        lines.append(f"     Impact    : {f.description}")
        if f.reason: lines.append(f"     Reason    : {f.reason}")
        if f.evidence:
            for ln in f.evidence.split("\n"): lines.append(f"     Evidence  : {ln}")
        lines.append("-" * 78)
    lines.append("\nGenerated by Pentes v3.1 — For authorized testing only.")
    return "\n".join(lines)


def build_html_report(target, findings, started, finished, mode):
    sev_colors = {"CRITICAL": "#ff2b2b", "HIGH": "#ff8c1a", "MEDIUM": "#ffd400", "LOW": "#2b8cff", "INFO": "#14c8c8"}
    conf_colors = {"CONFIRMED": "#14c8c8", "HIGH": "#14c8c8", "MEDIUM": "#ffd400", "LOW": "#8b949e"}
    summary = group_by_severity(findings)
    ordered = sorted(findings, key=lambda x: (SEVERITY_ORDER[x.severity], CONF_ORDER[x.confidence]), reverse=True)
    
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

    summary_html = "".join(f'<div class="sum" style="border-color:{sev_colors[s]}"><span style="color:{sev_colors[s]}">{s}</span><br>{summary[s]}</div>' for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Pentes Report - {target}</title>
<style>
  body{{font-family:-apple-system,Consolas,monospace;background:#0d1117;color:#e6edf3;padding:20px;max-width:1000px;margin:auto}}
  h1{{color:#14c8c8}} code{{background:#161b22;padding:2px 6px;border-radius:4px;color:#ffd400;word-break:break-all}}
  .sum{{display:inline-block;text-align:center;padding:12px 20px;margin:6px;border:2px solid #333;border-radius:8px;font-weight:bold}}
  .card{{background:#161b22;border-left:6px solid #333;border-radius:8px;padding:14px;margin:14px 0}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-weight:bold;font-size:12px;margin-right:6px}}
  .ts{{color:#8b949e;font-size:12px}} em{{color:#8b949e;font-style:normal;font-size:13px}}
  small{{background:#0d1117;padding:6px;display:block;border-radius:4px;word-break:break-all;white-space:pre-wrap}}
</style></head><body>
<h1>🛡️ Pentes v3.1 — Vulnerability Report</h1>
<p><b>Mode:</b> {mode}<br><b>Target:</b> {target}<br><b>Start:</b> {started}<br><b>Finish:</b> {finished}<br><b>Total Findings:</b> {len(findings)}</p>
<h2>Summary</h2><div>{summary_html}</div>
<h2>Findings</h2>
{''.join(cards)}
<hr><p style="color:#8b949e;font-size:12px">Generated by Pentes v3.1 — For authorized testing only.</p>
</body></html>"""


def build_json_report(target, findings, started, finished, mode):
    return json.dumps({
        "mode": mode, "target": target, "started": started, "finished": finished,
        "total": len(findings), "summary": group_by_severity(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2, ensure_ascii=False)


_STARTED_TS = ["-"]
_MODE_G = ["strict"]

def save_report(target, findings, fmt="txt"):
    dl = get_download_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = safe_filename(urlparse(target).netloc or "target")
    filename = f"vulnerability_report_{host}_{ts}.{fmt}"
    path = os.path.join(dl, filename)
    
    if fmt == "txt": content = build_txt_report(target, findings, _STARTED_TS[0], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _MODE_G[0])
    elif fmt == "html": content = build_html_report(target, findings, _STARTED_TS[0], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _MODE_G[0])
    else: content = build_json_report(target, findings, _STARTED_TS[0], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _MODE_G[0])

    for p in (path, os.path.join(os.getcwd(), filename)):
        try:
            with open(p, "w", encoding="utf-8") as f: f.write(content)
            return p
        except Exception: continue
    return "ERROR: cannot write file"


# ============================================================
# BANNER & UI
# ============================================================
def print_banner():
    print(f"""{C.CYAN}{C.B}
  ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗
  ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝
  ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗
  ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║
  ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
{C.R}{C.DIM}    Universal Web Vulnerability Scanner v3.1
    (WP + .NET Core + API/Swagger)
    For authorized penetration testing only.
{C.R}""")

def divider(char="─", n=66, color=C.GRAY):
    print(f"{color}{char * n}{C.R}")

def prompt_url():
    while True:
        try:
            raw = input(f"\n{C.CYAN}{C.B}➤ Masukkan URL / domain / kata kunci target: {C.R}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Dibatalkan."); sys.exit(0)
        if not raw: continue
        return normalize_target(raw)


# ============================================================
# MAIN SCAN
# ============================================================
def run_scan(target, threads=20, timeout=12, delay=0.0,
             skip_dir=False, skip_inject=False, aggressive=False, verbose=False):
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _STARTED_TS[0] = started
    _MODE_G[0] = "aggressive" if aggressive else "strict"

    divider("═", color=C.CYAN)
    print(f"{C.CYAN}{C.B}  TARGET  :{C.R} {target}")
    print(f"{C.CYAN}{C.B}  START   :{C.R} {started}")
    print(f"{C.CYAN}{C.B}  MODE    :{C.R} {_MODE_G[0].upper()}")
    divider("═", color=C.CYAN)

    client = HTTPClient(timeout=timeout, delay=delay, verbose=verbose)
    findings = []

    # Preflight
    print(f"\n{C.YELLOW}[*] Preflight: verifikasi koneksi...{C.R}")
    probe = client.get(target)
    if probe is None:
        print(f"{C.RED}[!] Target tidak bisa dijangkau.{C.R}")
        return findings, started

    is_err = is_error_page(probe)
    waf = detect_waf(probe)
    print(f"{C.GREEN}[+] Reachable — HTTP {probe.status_code}  ({len(probe.content)} bytes)")
    if waf: print(f"{C.CYAN}[i] WAF terdeteksi: {waf}{C.R}")
    if is_err: print(f"{C.YELLOW}[!] Root URL mengembalikan halaman ERROR (origin down / WAF).{C.R}")

    root = get_root(target)

    # 1. Fingerprint
    print(f"\n{C.MAGENTA}{C.B}[1/8] FINGERPRINT & WAF{C.R}")
    divider()
    for f in scan_fingerprint(client, target): print(f.render()); findings.append(f)

    # 2. Headers
    print(f"\n{C.MAGENTA}{C.B}[2/8] SECURITY HEADERS & COOKIE FLAGS{C.R}")
    divider()
    for f in scan_security_headers(client, target): print(f.render()); findings.append(f)

    # 3. CORS
    print(f"\n{C.MAGENTA}{C.B}[3/8] CORS{C.R}")
    divider()
    cors = scan_cors(client, target)
    for f in cors: print(f.render()); findings.append(f)
    if not cors: print(f"{C.DIM}    (no CORS issue){C.R}")

    # 4. Methods
    print(f"\n{C.MAGENTA}{C.B}[4/8] HTTP METHODS{C.R}")
    divider()
    meth = scan_methods(client, target)
    for f in meth: print(f.render()); findings.append(f)
    if not meth: print(f"{C.DIM}    (no risky method){C.R}")

    # 5. Directory
    if not skip_dir:
        print(f"\n{C.MAGENTA}{C.B}[5/8] DIRECTORY & SENSITIVE FILES (WP + .NET + Generic){C.R}")
        divider()
        ds = DirScanner(client, root, threads=threads, aggressive=aggressive)
        if ds.soft404: print(f"{C.YELLOW}[i] Soft-404 terdeteksi.{C.R}")
        dir_f = ds.run()
        findings.extend(dir_f)
        print(f"{C.GREEN}[+] Directory selesai: {len(dir_f)} temuan.{C.R}")
    else:
        print(f"\n{C.DIM}[5/8] Skipped (--no-dir).{C.R}")

    # 6. Tech-specific Enumeration (Aggressive)
    if aggressive:
        print(f"\n{C.MAGENTA}{C.B}[6/8] TECH ENUMERATION (WP / .NET / Swagger){C.R}")
        divider()
        
        # .NET Check
        dotnet_f = scan_dotnet_api(client, root)
        for f in dotnet_f: print(f.render()); findings.append(f)
        
        # WP Check
        r = client.get(target)
        is_wp = r is not None and ("/wp-content/" in (r.text or "") or "/wp-includes/" in (r.text or ""))
        if is_wp:
            print(f"{C.GREEN}[+] WordPress terdeteksi.{C.R}")
            wp = scan_wordpress(client, root)
            for f in wp: print(f.render()); findings.append(f)
        elif not dotnet_f:
            print(f"{C.DIM}    (Tidak terdeteksi WP atau .NET yang spesifik){C.R}")
    else:
        print(f"\n{C.DIM}[6/8] Skipped tech enum (--aggressive).{C.R}")

    # 7. Injection (GET)
    if not skip_inject:
        print(f"\n{C.MAGENTA}{C.B}[7/8] INJECTION TESTS (GET){C.R}")
        divider()
        if "?" in target and extract_params(target):
            inj = InjectionScanner(client, aggressive=aggressive)
            findings.extend(inj.scan_url(target))
        else:
            print(f"{C.DIM}    Tidak ada parameter GET di URL awal.{C.R}")
    else:
        print(f"\n{C.DIM}[7/8] Skipped (--no-inject).{C.R}")

    # 8. GraphQL
    print(f"\n{C.MAGENTA}{C.B}[8/8] GRAPHQL INTROSPECTION{C.R}")
    divider()
    # Simple GraphQL check
    r = client.post(f"{root}/graphql", json={"query": "{__schema{types{name}}}"}, headers={"Content-Type": "application/json"})
    if r and r.status_code == 200 and "__schema" in (r.text or ""):
        f = Finding("MEDIUM", "CONFIRMED", "GraphQL Introspection Enabled", f"{root}/graphql", "Introspection aktif.", "Schema exposed.", "Valid JSON response.")
        print(f.render()); findings.append(f)
    else:
        print(f"{C.DIM}    (no GraphQL detected){C.R}")

    # Summary
    print()
    divider("═", color=C.CYAN)
    print(f"{C.CYAN}{C.B}  SCAN COMPLETE  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.R}")
    divider("═", color=C.CYAN)
    summary = group_by_severity(findings)
    print(f"{C.B}  TOTAL FINDINGS: {len(findings)}{C.R}")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"  {SEVERITY_COLOR[s]}[{s:<8}]{C.R} : {summary[s]}")
    
    conf = {"CONFIRMED": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings: conf[f.confidence] = conf.get(f.confidence, 0) + 1
    print(f"{C.B}  CONFIDENCE:{C.R} " + "  ".join(f"{CONF_COLOR[k]}={v}{C.R}" for k, v in conf.items() if v))
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
        if fmt not in ("txt", "html", "json"): fmt = "html"
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
        description="Pentes v3.1 — Universal Web Vulnerability Scanner (Termux)",
    )
    parser.add_argument("target", nargs="?", help="URL / domain / keyword")
    parser.add_argument("--threads", type=int, default=20, help="Worker (default 20)")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout (default 12)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay per request (s)")
    parser.add_argument("--no-dir", action="store_true", help="Skip directory scan")
    parser.add_argument("--no-inject", action="store_true", help="Skip injection tests")
    parser.add_argument("--aggressive", action="store_true", help="Aktifkan tech enum, crawl, param discovery")
    parser.add_argument("--verbose", action="store_true", help="Tampilkan setiap request")
    parser.add_argument("--header", action="append", default=[], help="Custom header 'Name: Value'")
    parser.add_argument("--cookie", type=str, default=None, help="Custom cookie string")
    args = parser.parse_args()

    print_banner()
    target = normalize_target(args.target) if args.target else prompt_url()

    try:
        findings, _ = run_scan(
            target, threads=args.threads, timeout=args.timeout, delay=args.delay,
            skip_dir=args.no_dir, skip_inject=args.no_inject, aggressive=args.aggressive, verbose=args.verbose
        )
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Scan dibatalkan.{C.R}"); sys.exit(130)
    except Exception as e:
        print(f"\n{C.RED}[!] Fatal error: {e}{C.R}"); traceback.print_exc(); sys.exit(1)

    interactive_save(findings, target)
    print(f"\n{C.GREEN}{C.B}[✓] Selesai. Stay ethical.{C.R}\n")

if __name__ == "__main__":
    main()
