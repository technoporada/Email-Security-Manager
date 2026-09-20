"""Abuse reporter — generates and sends abuse reports."""
from typing import Dict, List
from datetime import datetime, timezone
from config import ABUSE_TEMPLATES


def generate_report(
    report_type: str,
    source_ip: str = "",
    domain: str = "",
    url: str = "",
    evidence: str = "",
    reporter_name: str = "[YOUR_NAME]",
    reporter_email: str = "[YOUR_EMAIL]",
) -> Dict:
    template = ABUSE_TEMPLATES.get(report_type)
    if not template:
        return {"error": f"Unknown report type: {report_type}"}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    body = f"""Subject: {template['subject']}

Dear Abuse Team,

I am reporting malicious activity originating from your network/service:

**Incident Details:**
- Date/Time: {now}
- Source IP: {source_ip or '[IP_ADDRESS]'}
- Domain: {domain or '[DOMAIN_NAME]'}
- URL: {url or '[PHISHING_URL]'}

**Evidence:**
{evidence or '- Email headers attached/below\n- Malicious content detected'}

**Request:**
Please investigate and take appropriate action to stop this activity.
The source appears to be compromised or being used for malicious purposes.

**Contact:**
If you need additional information, please contact {reporter_email}.

Best regards,
{reporter_name}
{reporter_email}"""

    return {
        "type": report_type,
        "subject": template["subject"],
        "body": body,
        "contacts": template["contacts"],
    }


def get_all_templates() -> Dict[str, Dict]:
    result = {}
    for key, template in ABUSE_TEMPLATES.items():
        result[key] = {
            "name": key,
            "subject": template["subject"],
            "contacts": template["contacts"],
        }
    return result
