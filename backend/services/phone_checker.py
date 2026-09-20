"""Phone checker — scrapes Polish free databases (Tellows, NieNaDzwoń, etc.)."""
import re
from typing import Dict, List, Optional
import httpx
from services.rate_limiter import RateLimiter

limiter = RateLimiter()


async def check_phone(phone: str) -> Dict:
    clean = re.sub(r"[\s\-\(\)\+]", "", phone)

    result = {
        "phone": phone,
        "clean": clean,
        "country": _detect_country(clean),
        "risk": "unknown",
        "reports": 0,
        "categories": [],
        "databases": {},
    }

    # Check each Polish database
    for db_name, url_template in _get_db_urls(clean).items():
        if limiter.can_request("phone"):
            db_result = await _scrape_database(db_name, url_template)
            if db_result:
                result["databases"][db_name] = db_result
                result["reports"] += db_result.get("reports", 0)
                result["categories"].extend(db_result.get("categories", []))

    # Deduplicate categories
    result["categories"] = list(set(result["categories"]))

    # Determine risk
    if result["reports"] > 100:
        result["risk"] = "high"
    elif result["reports"] > 10:
        result["risk"] = "medium"
    elif result["reports"] > 0:
        result["risk"] = "low"
    else:
        result["risk"] = "unknown"

    # Cache
    limiter.set_cache("phone", phone, result)

    return result


def _detect_country(phone: str) -> str:
    if phone.startswith("48"):
        return "Poland"
    if phone.startswith("49"):
        return "Germany"
    if phone.startswith("44"):
        return "UK"
    if phone.startswith("1"):
        return "USA"
    if phone.startswith("33"):
        return "France"
    return "Unknown"


def _get_db_urls(phone: str) -> Dict[str, str]:
    return {
        "tellows": f"https://www.tellows.pl/num/{phone}",
        "nienadzwon": f"https://nienadzwon.pl/numer/{phone}",
        "jakitonumer": f"https://www.jakitonumer.pl/numer/{phone}",
    }


async def _scrape_database(db_name: str, url: str) -> Optional[Dict]:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                    "Accept-Language": "pl-PL,pl;q=0.9",
                }
            )
            if resp.status_code == 200:
                return _parse_response(db_name, resp.text)
    except Exception:
        pass
    return None


def _parse_response(db_name: str, html: str) -> Optional[Dict]:
    if db_name == "tellows":
        return _parse_tellows(html)
    elif db_name == "nienadzwon":
        return _parse_nienadzwon(html)
    elif db_name == "jakitonumer":
        return _parse_jakitonumer(html)
    return None


def _parse_tellows(html: str) -> Optional[Dict]:
    reports = 0
    categories = []

    # Extract report count
    match = re.search(r"(\d+)\s*(?:ocen|zgłoszeń|reports)", html, re.IGNORECASE)
    if match:
        reports = int(match.group(1))

    # Extract categories
    cat_matches = re.findall(r'class="[^"]*tag[^"]*"[^>]*>([^<]+)<', html)
    categories = [c.strip() for c in cat_matches if c.strip()]

    return {"reports": reports, "categories": categories, "source": "tellows"}


def _parse_nienadzwon(html: str) -> Optional[Dict]:
    reports = 0
    categories = []

    match = re.search(r"(\d+)\s*(?:zgłoszeń|komentarzy)", html, re.IGNORECASE)
    if match:
        reports = int(match.group(1))

    cat_matches = re.findall(r'<span[^>]*class="[^"]*category[^"]*"[^>]*>([^<]+)</span>', html, re.IGNORECASE)
    categories = [c.strip() for c in cat_matches if c.strip()]

    return {"reports": reports, "categories": categories, "source": "nienadzwon"}


def _parse_jakitonumer(html: str) -> Optional[Dict]:
    reports = 0
    categories = []

    match = re.search(r"(\d+)\s*(?:komentarzy|ocen)", html, re.IGNORECASE)
    if match:
        reports = int(match.group(1))

    cat_matches = re.findall(r'<td[^>]*class="[^"]*cat[^"]*"[^>]*>([^<]+)</td>', html, re.IGNORECASE)
    categories = [c.strip() for c in cat_matches if c.strip()]

    return {"reports": reports, "categories": categories, "source": "jakitonumer"}
