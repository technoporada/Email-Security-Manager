"""Link checker — ZERO API keys. All scraping."""
import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse
import httpx
from services.rate_limiter import RateLimiter
from config import SUSPICIOUS_TLDS, URL_SHORTENERS

limiter = RateLimiter()


async def check_url(url: str) -> Dict:
    result = {
        "url": url,
        "safe": True,
        "risks": [],
        "verdict": "safe",
        "details": {},
    }

    # 1. Local analysis (always works, no API)
    local = _local_analysis(url)
    result["risks"].extend(local["risks"])

    # 2. Resolve domain → IP
    domain = _extract_domain(url)
    ip = None
    if domain:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            pass

    # 3. ip-api (free, no auth, 45/min)
    if ip and limiter.can_request("ip_api"):
        ip_info = await _ip_api_check(ip)
        result["details"]["ip_info"] = ip_info

    # 4. Scrape AbuseIPDB page (no API key)
    if ip and limiter.can_request("abuseipdb"):
        abuse = await _scrape_abuseipdb(ip)
        result["details"]["abuseipdb"] = abuse
        if abuse.get("abuse_confidence", 0) > 50:
            result["risks"].append(f"AbuseIPDB: {abuse['abuse_confidence']}% abuse confidence")
            result["safe"] = False

    # 5. Scrape VirusTotal page (no API key)
    if limiter.can_request("virustotal"):
        vt = await _scrape_virustotal(url)
        result["details"]["virustotal"] = vt
        if vt.get("malicious", 0) > 0:
            result["risks"].append(f"VirusTotal: {vt['malicious']} engines flag as malicious")
            result["safe"] = False

    # 6. OTX (free, generous)
    if domain and limiter.can_request("otx"):
        otx = await _otx_check(domain)
        result["details"]["otx"] = otx
        if otx.get("pulse_count", 0) > 0:
            result["risks"].append(f"OTX: {otx['pulse_count']} threat pulses")
            result["safe"] = False

    # Update verdict
    if result["risks"]:
        result["verdict"] = "suspicious" if result["safe"] else "malicious"
    else:
        result["verdict"] = "safe"

    limiter.set_cache("url", url, result)
    return result


def _local_analysis(url: str) -> Dict:
    risks = []

    for tld in SUSPICIOUS_TLDS:
        if url.lower().endswith(tld) or f"{tld}/" in url.lower():
            risks.append(f"Suspicious TLD: {tld}")
            break

    for shortener in URL_SHORTENERS:
        if shortener in url.lower():
            risks.append(f"URL shortener: {shortener}")
            break

    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        risks.append("IP address used instead of domain name")

    suspicious = ["login", "verify", "secure", "account", "update", "confirm", "banking", "urgent"]
    for kw in suspicious:
        if kw in url.lower():
            risks.append(f"Suspicious keyword: {kw}")
            break

    return {"risks": risks}


async def _ip_api_check(ip: str) -> Dict:
    """ip-api.com — free, no auth, 45 req/min."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,city,isp,org,as,proxy,hosting")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query"),
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as"),
                        "proxy": data.get("proxy", False),
                        "hosting": data.get("hosting", False),
                    }
    except Exception:
        pass
    return {"error": "ip-api failed"}


async def _scrape_abuseipdb(ip: str) -> Dict:
    """Scrape AbuseIPDB page — no API key needed."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(
                f"https://www.abuseipdb.com/check/{ip}",
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
            )
            if resp.status_code == 200:
                html = resp.text
                confidence = 0
                match = re.search(r"(\d+)%", html)
                if match:
                    confidence = int(match.group(1))

                reports = 0
                match = re.search(r"(\d[\d,]*)\s*(?:reports|zgłoszeń)", html, re.IGNORECASE)
                if match:
                    reports = int(match.group(1).replace(",", ""))

                return {
                    "ip": ip,
                    "abuse_confidence": confidence,
                    "total_reports": reports,
                }
    except Exception:
        pass
    return {"error": "scrape failed"}


async def _scrape_virustotal(url: str) -> Dict:
    """Scrape VirusTotal page — no API key needed."""
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(
                f"https://www.virustotal.com/gui/url/{url}",
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
            )
            if resp.status_code == 200:
                html = resp.text
                malicious = 0
                # Look for detection counts in the page
                match = re.search(r'"malicious":\s*(\d+)', html)
                if match:
                    malicious = int(match.group(1))

                return {
                    "malicious": malicious,
                    "source": "scraped",
                }
    except Exception:
        pass
    return {"error": "scrape failed"}


async def _otx_check(domain: str) -> Dict:
    """OTX AlienVault — free, generous (10k/hr)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
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
    return {"error": "OTX failed"}


def _extract_domain(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return parsed.hostname
    except Exception:
        return None
