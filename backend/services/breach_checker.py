"""Breach checker — HIBP k-anonymity for passwords (no account needed)."""
import hashlib
import httpx
from typing import Dict


async def check_password(password: str) -> Dict:
    """Check if a password appears in known breaches via HIBP k-anonymity.

    Only the first 5 chars of the SHA-1 hash are sent to the API.
    The full hash never leaves the client.
    """
    if not password:
        return {"error": "empty password"}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true"},
            )
        if resp.status_code != 200:
            return {"error": f"HIBP returned {resp.status_code}"}
    except httpx.HTTPError as e:
        return {"error": f"network error: {e}"}

    count = 0
    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1])
            break

    return {
        "breached": count > 0,
        "count": count,
        "message": (
            f"Password found in {count} breach(es) — change it immediately!"
            if count > 0
            else "Password not found in known breaches."
        ),
    }
