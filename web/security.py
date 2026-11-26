import ipaddress
import logging
import time

from fastapi import HTTPException, Request

from core.database import get_db

log = logging.getLogger("aegisedr.security")

_LOOPBACK = {"127.0.0.1", "::1"}


def client_ip(request: Request) -> str:
    """Client address for audit and rate limits.

    X-Real-IP is honored only when the TCP peer is loopback, which is the
    nginx on this host. A client that can connect directly cannot spoof it.
    """
    peer = request.client.host if request.client else ""
    if peer in _LOOPBACK:
        forwarded = request.headers.get("x-real-ip", "").strip()
        if forwarded and _is_ip(forwarded):
            return forwarded
    return peer or "unknown"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def rate_limit(bucket: str, max_requests: int, window_seconds: int):
    """Persistent per-bucket limit. Survives a console restart."""
    now = time.time()
    cutoff = now - window_seconds
    db = await get_db()
    async with db:
        await db.execute("DELETE FROM rate_limits WHERE ts < ?", (cutoff,))
        async with db.execute(
            "SELECT COUNT(*) FROM rate_limits WHERE bucket=? AND ts>=?",
            (bucket, cutoff),
        ) as cur:
            count = (await cur.fetchone())[0]
        if count >= max_requests:
            raise HTTPException(status_code=429, detail="Too many requests")
        await db.execute(
            "INSERT INTO rate_limits (bucket, ts) VALUES (?,?)",
            (bucket, now),
        )
        await db.commit()


async def audit(user: str | None, action: str, details: str | None, ip: str | None):
    try:
        db = await get_db()
        async with db:
            await db.execute(
                "INSERT INTO audit_log (user, action, details, ip_address) VALUES (?,?,?,?)",
                (user, action, details, ip),
            )
            await db.commit()
    except Exception:
        log.exception("audit log write failed for %s", action)
