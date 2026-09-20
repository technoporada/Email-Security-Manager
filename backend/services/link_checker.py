"""Link checker — VirusTotal free, AbuseIPDB free, OTX free, ip-api free."""
import asyncio
from typing import Dict, List, Optional
import httpx
from services.rate_limiter import RateLimiter
from config import (
    VIRUSTOTAL_KEY, ABUSEIPDB_KEY, OTX_KEY,
    SUSPICIOUS_TLDS, URL_SHORTENERS
)

limiter = RateLimiter()


async def check_url(url: str) -> Dict:
    result = {
        "url": url,
        "safe": True,
        "risks": [],
        "verdict": "safe",
        "details": {},
    }

    # Local analysis first (no API needed)
    local = _local_analysis(url)
    result["risks"].extend(local["risks"])
    if local["risks"]:
        result["safe"] = False
        result["verdict"] = "suspicious"

    # VirusTotal (free: 4 req/min)
    if VIRUSTOTAL_KEY and limiter.can_request("virustotal"):
        vt = await _virustotal_check(url)
        result["details"]["virustotal"] = vt
        if vt.get("malicious", 0) > 0:
            result["safe"] = False
            result["verdict"] = "malicious"
            result["risks"].append(f"VirusTotal: {vt['malicious']} engines flag as malicious")

    # AbuseIPDB (free: 60 req/min)
    domain = _extract_domain(url)
    if domain and ABUSEIPDB_KEY and limiter.can_request("abuseipdb"):
        ab = await _abuseipdb_check(domain)
        result["details"]["abuseipdb"] = ab
        if ab.get("abuse_confidence", 0) > 50:
            result["safe"] = False
            result["verdict"] = "suspicious"
            result["risks"].append(f"AbuseIPDB: {ab['abuse_confidence']}% abuse confidence")

    # OTX AlienVault (free, generous)
    if domain and OTX_KEY and limiter.can_request("otx"):
        otx = await _otx_check(domain)
        result["details"]["otx"] = otx
        if otx.get("pulse_count", 0) > 0:
            result["safe"] = False
            result["verdict"] = "malicious"
            result["risks"].append(f"OTX: Found in {otx['pulse_count']} threat intelligence pulses")

    # IP-API (free, no key, 45 req/min)
    if limiter.can_request("ip_api") and domain:
        ip_info = await _ip_api_check(domain)
        result["details"]["ip_info"] = ip_info

    # Update verdict
    if not result["risks"]:
        result["verdict"] = "safe"
    elif result["verdict"] == "safe":
        result["verdict"] = "suspicious"

    # Cache result
    limiter.set_cache("url", url, result)

    return result


def _local_analysis(url: str) -> Dict:
    risks = []

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if url.lower().endswith(tld) or f"{tld}/" in url.lower():
            risks.append(f"Suspicious TLD: {tld}")
            break

    # URL shorteners
    for shortener in URL_SHORTENERS:
        if shortener in url.lower():
            risks.append(f"URL shortener: {shortener}")
            break

    # IP address instead of domain
    import re
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        risks.append("IP address used instead of domain name")

    # Suspicious keywords
    suspicious = ["login", "verify", "secure", "account", "update", "confirm", "banking", "urgent"]
    for kw in suspicious:
        if kw in url.lower():
            risks.append(f"Suspicious keyword in URL: {kw}")
            break

    return {"risks": risks}


async def _virustotal_check(url: str) -> Dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                params={"url": url}
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": data.get("malicious", 0),
                    "suspicious": data.get("suspicious", 0),
                    "harmless": data.get("harmless", 0),
                    "undetected": data.get("undetected", 0),
                }
    except Exception:
        pass
    return {"error": "API request failed"}


async def _abuseipdb_check(domain: str) -> Dict:
    try:
        # Resolve domain to IP first
        import socket
        ip = socket.gethostbyname(domain)

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90}
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "ip": data.get("ipAddress"),
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "usage_type": data.get("usageType"),
                }
    except Exception:
        pass
    return {"error": "API request failed"}


async def _otx_check(domain: str) -> Dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": OTX_KEY} if OTX_KEY else {}
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name"),
                    "alexa": data.get("alexa", ""),
                }
    except Exception:
        pass
    return {"error": "API request failed"}


async def _ip_api_check(domain: str) -> Dict:
    try:
        import socket
        ip = socket.gethostbyname(domain)

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                }
    except Exception:
        pass
    return {"error": "API request failed"}


def _extract_domain(url: str) -> Optional[str]:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return parsed.hostname
    except Exception:
        return None
