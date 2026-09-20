"""Email Security Manager — FastAPI backend."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import Optional
import os

from database import Database
from services.email_parser import parse_headers
from services.link_checker import check_url
from services.phone_checker import check_phone
from services.abuse_reporter import generate_report, get_all_templates
from services.rate_limiter import RateLimiter

db = Database()
limiter = RateLimiter()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    limiter.cleanup()


app = FastAPI(
    title="Email Security Manager",
    description="Email threat analysis, link checking, phone scam detection, abuse reporting",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path) as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Email Security Manager</h1><p>Frontend not found.</p>")


# === Email Analysis ===

@app.post("/api/email/parse")
async def api_parse_email(headers: str = Query(..., description="Raw email headers")):
    result = parse_headers(headers)
    db.save_scan("email_headers", result.get("from", "unknown"), result, result.get("risk_score", 0))
    return result


# === Link Checking ===

@app.get("/api/link/check")
async def api_check_link(url: str = Query(..., description="URL to check")):
    cached = limiter.get_cached("url", url)
    if cached:
        return cached
    result = await check_url(url)
    db.save_scan("link_check", url, result, len(result.get("risks", [])))
    return result


# === Phone Checking ===

@app.get("/api/phone/check")
async def api_check_phone(phone: str = Query(..., description="Phone number")):
    cached = limiter.get_cached("phone", phone)
    if cached:
        return cached
    result = await check_phone(phone)
    db.save_scan("phone_check", phone, result, result.get("reports", 0))
    return result


@app.get("/api/phone/databases")
async def api_phone_databases():
    from config import PHONE_DATABASES
    return PHONE_DATABASES


# === Abuse Reporting ===

@app.get("/api/abuse/templates")
async def api_abuse_templates():
    return get_all_templates()


@app.post("/api/abuse/generate")
async def api_generate_abuse_report(
    report_type: str = Query(...),
    source_ip: str = Query(""),
    domain: str = Query(""),
    url: str = Query(""),
    evidence: str = Query(""),
):
    result = generate_report(report_type, source_ip, domain, url, evidence)
    if "error" not in result:
        db.save_abuse_report(report_type, domain or source_ip or url, result["body"], result["contacts"])
    return result


# === Blacklist ===

@app.get("/api/blacklist")
async def api_get_blacklist(entry_type: Optional[str] = None):
    return db.get_blacklist(entry_type)


@app.post("/api/blacklist/add")
async def api_add_blacklist(
    entry_type: str = Query(...),
    value: str = Query(...),
    reason: str = Query(""),
):
    success = db.add_blacklist(entry_type, value, reason)
    return {"success": success, "value": value}


@app.delete("/api/blacklist/remove")
async def api_remove_blacklist(value: str = Query(...)):
    success = db.remove_blacklist(value)
    return {"success": success}


@app.get("/api/blacklist/check")
async def api_check_blacklist(
    entry_type: str = Query(...),
    value: str = Query(...),
):
    return {"blacklisted": db.is_blacklisted(entry_type, value)}


# === History & Stats ===

@app.get("/api/history")
async def api_history(scan_type: Optional[str] = None, limit: int = 50):
    return db.get_scans(scan_type, limit)


@app.get("/api/stats")
async def api_stats():
    return db.get_stats()


# === Rate Limit Status ===

@app.get("/api/ratelimit")
async def api_ratelimit_status():
    return {
        "virustotal": {
            "can_request": limiter.can_request("virustotal"),
            "wait_seconds": limiter.wait_time("virustotal"),
        },
        "abuseipdb": {
            "can_request": limiter.can_request("abuseipdb"),
            "wait_seconds": limiter.wait_time("abuseipdb"),
        },
        "urlscan": {
            "can_request": limiter.can_request("urlscan"),
            "wait_seconds": limiter.wait_time("urlscan"),
        },
    }
