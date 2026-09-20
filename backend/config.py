"""Configuration — free APIs, rate limits, cache TTL."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "email_security.db"))
RATELIMIT_PATH = os.getenv("RATELIMIT_PATH", str(BASE_DIR / "ratelimit.db"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
BLACKLIST_ENTRY_TYPES = {"ip", "domain", "email", "phone"}

# Rate limits (requests per minute)
RATE_LIMITS = {
    "virustotal": 4,       # Free: 4 req/min, 500/day
    "abuseipdb": 10,       # Free: 1,000/day = ~0.7/min avg, burst up to ~10
    "urlscan": 3,          # Free: ~3 req/s but we limit
    "otx": 100,            # Free: 10,000/hour
    "ip_api": 45,          # Free: 45 req/min
}

# Cache TTL in seconds
CACHE_TTL = {
    "url": 1800,
    "virustotal": 3600,    # 1h
    "abuseipdb": 1800,     # 30min
    "urlscan": 3600,
    "phone": 86400,        # 24h
    "ip": 1800,
}

# API keys — NOT NEEDED. Everything uses scraping.
VIRUSTOTAL_KEY = ""  # Not needed
ABUSEIPDB_KEY = ""  # Not needed
URLSCAN_KEY = ""  # Not needed
OTX_KEY = ""  # Not needed

# Suspicious TLDs
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".ru", ".cn", ".top", ".xyz", ".buzz", ".click", ".link"]

# URL shorteners
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "short.link"]

# Phone scam databases (Polish)
PHONE_DATABASES = {
    "tellows": "https://www.tellows.pl/num/{phone}",
    "nienadzwon": "https://nienadzwon.pl/numer/{phone}",
    "jakitonumer": "https://www.jakitonumer.pl/numer/{phone}",
    "whocalled": "https://whocalled.pl/numer/{phone}",
}

# Abuse report templates
ABUSE_TEMPLATES = {
    "hosting": {
        "subject": "Abuse Report — Spam/Phishing from your network",
        "contacts": ["abuse@digitalocean.com", "abuse@vultr.com", "abuse@linode.com", "abuse@aws.amazon.com"],
    },
    "domain": {
        "subject": "Domain Abuse Report — Phishing/Fraudulent Activity",
        "contacts": ["abuse@namecheap.com", "abuse@godaddy.com", "abuse@name.com", "abuse@porkbun.com"],
    },
    "isp": {
        "subject": "Network Abuse Report — Spam Activity",
        "contacts": ["abuse@isp-name.com"],
    },
    "cloudflare": {
        "subject": "Cloudflare Abuse Report — Phishing Site",
        "contacts": ["abuse@cloudflare.com"],
    },
}
