# Email Security Manager

[![CI](https://github.com/technoporada/Email-Security-Manager/actions/workflows/ci.yml/badge.svg)](https://github.com/technoporada/Email-Security-Manager/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Email threat analysis, link checking, phone scam detection, abuse reporting.**

Free APIs only — no paid keys required. Works without API keys (local analysis), better with free tier keys.

> **Keywords:** `email-security` `phishing` `link-checker` `phone-scam` `abuse-report` `osint` `fastapi` `python`

---

## Features

| Module | What it does |
|--------|-------------|
| **Email Headers** | Parse raw headers, extract IPs/domains, check SPF/DKIM/DMARC |
| **Link Checker** | VirusTotal, AbuseIPDB, OTX AlienVault, ip-api, local analysis |
| **Phone Check** | Scrape Tellows, NieNaDzwoń, JakiToNumer for scam reports |
| **Abuse Report** | Generate abuse reports for hosting/domain/ISP/Cloudflare |
| **Blacklist** | Maintain local blacklist of IPs, domains, emails, phones |
| **History** | SQLite-backed scan history with stats |

## Free APIs Used

| API | Free Tier | Key Required? |
|-----|-----------|---------------|
| **VirusTotal** | 4 req/min | Yes (free key) |
| **AbuseIPDB** | 60 req/min | Yes (free key) |
| **OTX AlienVault** | Generous | Optional |
| **ip-api.com** | 45 req/min | No |
| **Tellows/NieNaDzwoń** | Scraping | No |

**Without any API keys:** Local analysis still works (suspicious TLDs, URL shorteners, IP detection, header parsing).

## Quick Start

```bash
git clone https://github.com/technoporada/Email-Security-Manager.git
cd Email-Security-Manager/backend

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python app.py
# → http://127.0.0.1:8000
```

## Optional: API Keys

```bash
export VIRUSTOTAL_KEY="your-free-key"
export ABUSEIPDB_KEY="your-free-key"
export OTX_KEY="your-free-key"  # optional
```

Get free keys:
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB: https://www.abuseipdb.com/account/api
- OTX: https://otx.alienvault.com/api

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/email/parse?headers=` | POST | Parse email headers |
| `/api/link/check?url=` | GET | Check URL safety |
| `/api/phone/check?phone=` | GET | Check phone number |
| `/api/phone/databases` | GET | List phone databases |
| `/api/abuse/templates` | GET | Get abuse report templates |
| `/api/abuse/generate` | POST | Generate abuse report |
| `/api/blacklist` | GET | Get blacklist |
| `/api/blacklist/add` | POST | Add to blacklist |
| `/api/blacklist/remove` | DELETE | Remove from blacklist |
| `/api/blacklist/check` | GET | Check if blacklisted |
| `/api/history` | GET | Scan history |
| `/api/stats` | GET | Dashboard stats |
| `/api/ratelimit` | GET | Rate limit status |

## Project Structure

```
Email-Security-Manager/
├── backend/
│   ├── app.py                 # FastAPI main
│   ├── config.py              # Configuration
│   ├── database.py            # SQLite models
│   ├── requirements.txt
│   └── services/
│       ├── rate_limiter.py    # API rate limiting + cache
│       ├── email_parser.py    # Header parsing (SPF/DKIM/DMARC)
│       ├── link_checker.py    # URL safety analysis
│       ├── phone_checker.py   # Phone scam detection
│       └── abuse_reporter.py  # Abuse report generation
├── frontend/
│   └── index.html             # Web UI
├── tests/
├── README.md
└── .github/workflows/ci.yml
```

## Chrome Extension (Android + Desktop)

Install the extension from `extension/` folder:
1. Open `chrome://extensions`
2. Enable Developer Mode
3. Click "Load unpacked" → select `extension/` folder
4. Right-click any phone number → "Check phone"
5. Right-click any link → "Check link"
6. Click extension icon → quick check tools

**Features:**
- Context menu: check phone numbers and links directly from any page
- Auto-copy high-risk phone numbers
- Abuse report templates (one-click copy)
- Toast notifications on pages
- Works on Android Chrome 119+

## PWA (Install on Android)

The frontend is also a PWA — open `http://your-server:8000` in Android Chrome and tap "Add to Home Screen".

## Tech Stack

- **Backend:** FastAPI + httpx + SQLite
- **Frontend:** Vanilla JS/CSS (dark theme) + PWA
- **Extension:** Chrome Manifest V3 (Android + Desktop)
- **APIs:** VirusTotal, AbuseIPDB, OTX, ip-api (all free tier)

## License

MIT

## Author

**technoporada** — [github.com/technoporada](https://github.com/technoporada)
