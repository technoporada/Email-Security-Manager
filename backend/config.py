"""Configuration — free APIs, rate limits, cache TTL."""
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///email_security.db")

# Rate limits (requests per minute)
RATE_LIMITS = {
    "virustotal": 4,       # Free tier: 4 req/min
    "abuseipdb": 60,       # Free tier: 60 req/min
    "urlscan": 3,          # Free tier: ~3 req/s but we limit
    "otx": 10,             # Free tier: generous
    "ip_api": 45,          # Free: 45 req/min
}

# Cache TTL in seconds
CACHE_TTL = {
    "virustotal": 3600,    # 1h
    "abuseipdb": 1800,     # 30min
    "urlscan": 3600,
    "phone": 86400,        # 24h
    "ip": 1800,
}

# API keys (optional — works without them but with lower limits)
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_KEY", "")
OTX_KEY = os.getenv("OTX_KEY", "")

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
