# 🛡️ Pentes — Accurate Web Vulnerability Scanner

> Web vulnerability scanner for Termux. Zero false-positive philosophy, confidence-scored findings, WAF-aware.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-green)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

## ⚠️ Disclaimer

**For authorized penetration testing only.** Only scan domains you own or have written permission to test. Unauthorized scanning is illegal (UU ITE Pasal 30 in Indonesia, CFAA in the US, etc.). The author is not responsible for misuse.

## ✨ Features

| Feature | Strict Mode | Aggressive Mode |
|---|---|---|
| Security headers & cookie flags | ✅ | ✅ |
| CORS misconfiguration | ✅ | ✅ |
| HTTP methods audit | ✅ | ✅ |
| Sensitive file discovery (content-validated) | ✅ | ✅ |
| GET injection tests (XSS / SQLi / LFI / Redirect) | ✅ | ✅ |
| Fingerprint + WAF detection | ✅ | ✅ |
| GraphQL introspection | ✅ | ✅ |
| Parameter discovery (Arjun-style) | ❌ | ✅ |
| Recursive crawler (depth 3) | ❌ | ✅ |
| Form extraction + POST injection | ❌ | ✅ |
| WordPress enumeration | ❌ | ✅ |
| Backup file fuzzing | ❌ | ✅ |
| WAF bypass tamper | ❌ | ✅ |

Every finding carries **severity + confidence + reason**. No finding without verbatim evidence.

## 📦 Installation (Termux)

```bash
pkg update -y && pkg upgrade -y
pkg install python git -y
pip install requests beautifulsoup4 colorama urllib3
termux-setup-storage

git clone https://github.com/USERNAME/pentes.git ~/pentes
cd ~/pentes
chmod +x pentes.py

echo "alias pentes='python ~/pentes/pentes.py'" >> ~/.bashrc
source ~/.bashrc
```

## 📦 Installation (Linux / macOS)

```bash
git clone https://github.com/USERNAME/pentes.git
cd pentes
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x pentes.py
./pentes.py --help
```

## 🚀 Usage

### Interactive
```bash
pentes
```

### Direct target
```bash
pentes example.com
pentes https://example.com
pentes "1.2.3.4:8080"
```

### Aggressive mode
```bash
pentes example.com --aggressive
```

### With cookie/auth
```bash
pentes example.com --aggressive --cookie "PHPSESSID=abc123"
pentes example.com --aggressive --header "Authorization: Bearer eyJ..."
```

### Verbose
```bash
pentes example.com --aggressive --verbose
```

### All options
```bash
pentes --help
```

## 📁 Output

Reports saved to `/storage/shared/Download/vulnerability_report_<host>_<timestamp>.<ext>`.

Format: TXT / HTML / JSON.

## 🎯 Confidence Levels

- **CONFIRMED** — verified with verbatim evidence (safe to act on)
- **HIGH** — strong signal, highly likely true
- **MEDIUM** — moderate signal, verify manually
- **LOW** — weak signal, transparency only

## ⚖️ License

MIT — see [LICENSE](LICENSE)
