"""Email header parser — extracts IPs, domains, SPF/DKIM/DMARC."""
import re
from typing import Dict, List, Optional


def parse_headers(raw_headers: str) -> Dict:
    result = {
        "from": _extract_header(raw_headers, "From"),
        "to": _extract_header(raw_headers, "To"),
        "subject": _extract_header(raw_headers, "Subject"),
        "date": _extract_header(raw_headers, "Date"),
        "message_id": _extract_header(raw_headers, "Message-ID"),
        "received": _extract_all_headers(raw_headers, "Received"),
        "ips": _extract_ips(raw_headers),
        "domains": _extract_domains(raw_headers),
        "spf": _parse_auth_result(raw_headers, "Authentication-Results", "spf"),
        "dkim": _parse_auth_result(raw_headers, "Authentication-Results", "dkim"),
        "dmarc": _parse_auth_result(raw_headers, "Authentication-Results", "dmarc"),
        "return_path": _extract_header(raw_headers, "Return-Path"),
        "x_mailer": _extract_header(raw_headers, "X-Mailer"),
        "reply_to": _extract_header(raw_headers, "Reply-To"),
    }

    # Risk indicators
    result["risks"] = _assess_risks(result)
    result["risk_score"] = len(result["risks"])

    return result


def _extract_header(headers: str, name: str) -> str:
    # Handle multi-line headers (continuation lines start with whitespace)
    pattern = rf"^{name}:\s*(.+?)(?:\n(?=\S)|\Z)"
    match = re.search(pattern, headers, re.MULTILINE | re.IGNORECASE | re.DOTALL)
    if match:
        # Join continuation lines
        raw = match.group(1)
        lines = [l.strip() for l in raw.split("\n") if l.strip()]
        return " ".join(lines)
    return ""


def _extract_all_headers(headers: str, name: str) -> List[str]:
    return re.findall(rf"^{name}:\s*(.+)$", headers, re.MULTILINE | re.IGNORECASE)


def _extract_ips(headers: str) -> List[str]:
    # IP from headers, exclude private ranges
    ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", headers)
    seen = set()
    result = []
    for ip in ips:
        if ip not in seen and not _is_private_ip(ip):
            seen.add(ip)
            result.append(ip)
    return result


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    first = int(parts[0])
    second = int(parts[1])
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    return False


def _extract_domains(headers: str) -> List[str]:
    # Match domains including multi-part TLDs (co.uk, etc.)
    domains = re.findall(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b",
        headers
    )
    seen = set()
    result = []
    for d in domains:
        d_lower = d.lower()
        if d_lower not in seen and "." in d_lower and not d_lower[0].isdigit():
            seen.add(d_lower)
            result.append(d_lower)
    return result


def _parse_auth_result(headers: str, header_name: str, mechanism: str) -> Optional[str]:
    auth_header = _extract_header(headers, header_name)
    if not auth_header:
        return None
    match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
    return match.group(1).lower() if match else None


def _assess_risks(result: Dict) -> List[str]:
    risks = []

    if result["spf"] == "fail":
        risks.append("SPF validation failed")
    elif result["spf"] == "softfail":
        risks.append("SPF softfail")

    if result["dkim"] == "fail":
        risks.append("DKIM validation failed")

    if result["dmarc"] == "fail":
        risks.append("DMARC validation failed")

    # Check for spoofed Reply-To
    if result["reply_to"] and result["from"]:
        from_domain = re.search(r"@([\w.-]+)", result["from"])
        reply_domain = re.search(r"@([\w.-]+)", result["reply_to"])
        if from_domain and reply_domain:
            if from_domain.group(1).lower() != reply_domain.group(1).lower():
                risks.append("Reply-To domain differs from From domain")

    # Check for suspicious X-Mailer
    suspicious_mailers = ["PHPMailer", "SwiftMailer", "mail()", "sendmail"]
    for mailer in suspicious_mailers:
        if mailer.lower() in (result["x_mailer"] or "").lower():
            risks.append(f"Suspicious X-Mailer: {mailer}")

    # Missing Message-ID
    if not result["message_id"]:
        risks.append("Missing Message-ID header")

    return risks
