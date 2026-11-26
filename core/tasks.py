"""Background console jobs: agent liveness and IoC refresh."""
import logging
from datetime import datetime, timezone

from config import AGENT_HEARTBEAT_TIMEOUT
from core.database import get_db

log = logging.getLogger("aegisedr.tasks")


async def mark_stale_endpoints_offline():
    window = f"-{int(AGENT_HEARTBEAT_TIMEOUT)} seconds"
    db = await get_db()
    async with db:
        await db.execute(
            """
            UPDATE endpoints
            SET status='offline'
            WHERE status='online'
              AND (last_seen IS NULL OR last_seen < datetime('now', ?))
            """,
            (window,),
        )
        # A scan can legitimately run for a long time. Anything still marked
        # running after six hours is an agent that never reported back.
        await db.execute(
            """
            UPDATE agent_commands
            SET status='queued', started_at=NULL
            WHERE status='running'
              AND started_at IS NOT NULL
              AND started_at < datetime('now', '-6 hours')
            """
        )
        await db.commit()


async def _setting(key: str, default: str = "") -> str:
    db = await get_db()
    async with db:
        async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else default


async def _set_setting(key: str, value: str):
    db = await get_db()
    async with db:
        await db.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?,?,datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, value),
        )
        await db.commit()


async def maybe_update_ioc_feeds():
    enabled = await _setting("ioc_auto_update", "1")
    if enabled != "1":
        return
    try:
        hours = int(await _setting("ioc_update_interval_hours", "6") or "6")
    except ValueError:
        hours = 6
    hours = min(max(hours, 1), 168)
    last_raw = await _setting("ioc_last_auto_update", "")
    now = datetime.now(timezone.utc).timestamp()
    try:
        last = float(last_raw) if last_raw else 0.0
    except ValueError:
        last = 0.0
    if now - last < hours * 3600:
        return
    # Stamp first so a slow feed cannot overlap with the next tick.
    await _set_setting("ioc_last_auto_update", str(now))
    from core.ioc_feeds import update_all_feeds
    log.info("Refreshing IoC feeds")
    await update_all_feeds()
