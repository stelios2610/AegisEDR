import asyncio
import httpx
import json
import re
from core.database import get_db

IP_PATTERN = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')
HASH_PATTERN = re.compile(r'^[a-fA-F0-9]{32,64}$')

async def update_all_feeds():
    db = await get_db()
    async with db:
        db.row_factory = __import__('aiosqlite').Row
        async with db.execute("SELECT * FROM ioc_feed_config WHERE enabled=1") as cur:
            feeds = [dict(r) for r in await cur.fetchall()]

    for feed in feeds:
        try:
            await update_feed(feed)
        except Exception as e:
            print(f"[IOC] Feed update failed: {feed['name']}: {e}")

async def update_feed(feed: dict):
    async with httpx.AsyncClient(timeout=30) as client:
        if feed["feed_type"] == "threatfox":
            await _update_threatfox(client, feed)
        elif feed["feed_type"] == "ip":
            await _update_ip_list(client, feed)
        elif feed["feed_type"] == "url":
            await _update_url_list(client, feed)
        elif feed["feed_type"] == "cisa":
            await _update_cisa(client, feed)

async def _bulk_insert_iocs(entries: list[tuple]):
    if not entries:
        return 0
    db = await get_db()
    async with db:
        count = 0
        for batch in _chunks(entries, 500):
            for entry in batch:
                try:
                    await db.execute(
                        "INSERT OR IGNORE INTO ioc_entries (ioc_type, value, threat_name, source, severity) VALUES (?,?,?,?,?)",
                        entry
                    )
                    count += 1
                except Exception:
                    pass
        await db.commit()
    return count

async def _update_ip_list(client: httpx.AsyncClient, feed: dict):
    resp = await client.get(feed["url"])
    entries = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split()[0]
        if IP_PATTERN.match(ip):
            entries.append(("ip", ip, "blocklist", feed["name"], "medium"))
    count = await _bulk_insert_iocs(entries)
    await _update_feed_stats(feed["id"], count)

async def _update_url_list(client: httpx.AsyncClient, feed: dict):
    resp = await client.get(feed["url"])
    entries = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            from urllib.parse import urlparse
            parsed = urlparse(line if "://" in line else "http://" + line)
            domain = parsed.netloc.split(":")[0].lower()
            if domain and DOMAIN_PATTERN.match(domain):
                entries.append(("domain", domain, "malware_url", feed["name"], "high"))
        except Exception:
            pass
    count = await _bulk_insert_iocs(entries)
    await _update_feed_stats(feed["id"], count)

async def _update_threatfox(client: httpx.AsyncClient, feed: dict):
    payload = {"query": "get_iocs", "days": 7}
    resp = await client.post(feed["url"], json=payload)
    data = resp.json()
    entries = []
    for item in data.get("data", []):
        ioc_type = item.get("ioc_type", "")
        value = item.get("ioc", "").strip().lower()
        threat = item.get("malware", "unknown")
        confidence = item.get("confidence_level", 50)
        severity = "critical" if confidence >= 90 else "high" if confidence >= 70 else "medium"
        if ioc_type == "ip:port":
            ip = value.split(":")[0]
            if IP_PATTERN.match(ip):
                entries.append(("ip", ip, threat, "ThreatFox", severity))
        elif ioc_type in ("domain", "url"):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value if "://" in value else "http://" + value)
                domain = parsed.netloc.split(":")[0]
                if domain and DOMAIN_PATTERN.match(domain):
                    entries.append(("domain", domain, threat, "ThreatFox", severity))
            except Exception:
                pass
        elif ioc_type in ("md5_hash", "sha256_hash", "sha1_hash"):
            if HASH_PATTERN.match(value):
                entries.append(("hash", value, threat, "ThreatFox", severity))
    count = await _bulk_insert_iocs(entries)
    await _update_feed_stats(feed["id"], count)

async def _update_cisa(client: httpx.AsyncClient, feed: dict):
    resp = await client.get(feed["url"])
    data = resp.json()
    entries = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cveID", "")
        if cve:
            entries.append(("cve", cve.lower(), vuln.get("vulnerabilityName", ""), "CISA KEV", "critical"))
    count = await _bulk_insert_iocs(entries)
    await _update_feed_stats(feed["id"], count)

async def _update_feed_stats(feed_id: int, count: int):
    db = await get_db()
    async with db:
        await db.execute("""
            UPDATE ioc_feed_config SET last_updated=datetime('now'), entry_count=? WHERE id=?
        """, (count, feed_id))
        await db.commit()

def _chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

async def check_hash_virustotal(file_hash: str, api_key: str) -> dict:
    if not api_key:
        return {}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers={"x-apikey": api_key})
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "total": sum(stats.values())
            }
    return {}

async def init_default_feeds():
    from config import IOC_FEEDS
    db = await get_db()
    async with db:
        for feed in IOC_FEEDS:
            await db.execute("""
                INSERT OR IGNORE INTO ioc_feed_config (name, url, feed_type, enabled)
                VALUES (?,?,?,1)
            """, (feed["name"], feed["url"], feed["type"]))
        await db.commit()
