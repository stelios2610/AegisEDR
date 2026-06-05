import json
import secrets
import time
from collections import defaultdict
from datetime import datetime
from fastapi import FastAPI, Request, Form, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from core.database import get_db
from core.scanner import (queue_scan, get_pending_commands, add_scan_event,
                           get_scan_events, register_ws, unregister_ws)
from web.auth import (authenticate_user, create_token, require_auth,
                      require_api_auth, hash_password, create_agent_token)

templates = Jinja2Templates(directory="web/templates")

# ── Rate limiting ─────────────────────────────────────────────────────────────
_rate_buckets: dict[str, list] = defaultdict(list)

def _rate_limit(key: str, max_requests: int, window_seconds: int):
    now = time.time()
    bucket = _rate_buckets[key]
    _rate_buckets[key] = [t for t in bucket if now - t < window_seconds]
    if len(_rate_buckets[key]) >= max_requests:
        raise HTTPException(status_code=429, detail="Too many requests")
    _rate_buckets[key].append(now)

# ── Path validation ───────────────────────────────────────────────────────────
def _safe_path(path: str | None) -> str | None:
    if not path:
        return None
    # Strip null bytes and limit length
    path = path.replace("\x00", "").strip()[:1024]
    return path if path else None

def register_routes(app: FastAPI):

    # ─── Auth ────────────────────────────────────────────────────────────────

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return templates.TemplateResponse("login.html", {"request": request, "error": None})

    @app.post("/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...)):
        _rate_limit(f"login:{request.client.host}", max_requests=10, window_seconds=60)
        user = await authenticate_user(username, password)
        if not user:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
        token = create_token(user["username"], user["role"])
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie("aegisedr_token", token, httponly=True, secure=True, samesite="lax", max_age=28800)
        db = await get_db()
        async with db:
            await db.execute("INSERT INTO audit_log (user, action, ip_address) VALUES (?,?,?)",
                             (username, "login", request.client.host))
            await db.commit()
        return resp

    @app.post("/logout")
    async def logout():
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie("aegisedr_token")
        return resp

    # ─── Dashboard ───────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("SELECT COUNT(*) as c FROM endpoints") as cur:
                total_endpoints = (await cur.fetchone())["c"]
            async with db.execute("SELECT COUNT(*) as c FROM endpoints WHERE status='online'") as cur:
                online_endpoints = (await cur.fetchone())["c"]
            async with db.execute("SELECT COUNT(*) as c FROM threats WHERE status='active'") as cur:
                active_threats = (await cur.fetchone())["c"]
            async with db.execute("SELECT COUNT(*) as c FROM threats WHERE severity='critical' AND status='active'") as cur:
                critical_threats = (await cur.fetchone())["c"]
            async with db.execute("SELECT COUNT(*) as c FROM quarantine WHERE restored=0") as cur:
                quarantine_count = (await cur.fetchone())["c"]
            async with db.execute("SELECT COUNT(*) as c FROM ioc_entries") as cur:
                ioc_count = (await cur.fetchone())["c"]
            async with db.execute("""
                SELECT t.*, e.hostname FROM threats t
                LEFT JOIN endpoints e ON t.endpoint_id=e.id
                ORDER BY t.detected_at DESC LIMIT 10
            """) as cur:
                recent_threats = [dict(r) for r in await cur.fetchall()]
            async with db.execute("""
                SELECT * FROM endpoints ORDER BY approved ASC, last_seen DESC LIMIT 10
            """) as cur:
                endpoints = [dict(r) for r in await cur.fetchall()]
            async with db.execute("SELECT COUNT(*) as c FROM endpoints WHERE approved=0") as cur:
                pending_count = (await cur.fetchone())["c"]

        return templates.TemplateResponse("dashboard.html", {
            "request": request, "user": user,
            "total_endpoints": total_endpoints, "online_endpoints": online_endpoints,
            "active_threats": active_threats, "critical_threats": critical_threats,
            "quarantine_count": quarantine_count, "ioc_count": ioc_count,
            "recent_threats": recent_threats, "endpoints": endpoints,
            "pending_count": pending_count
        })

    # ─── Endpoints ───────────────────────────────────────────────────────────

    @app.get("/endpoints", response_class=HTMLResponse)
    async def endpoints_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("""
                SELECT e.*,
                    (SELECT COUNT(*) FROM threats WHERE endpoint_id=e.id AND status='active') as active_threats
                FROM endpoints e ORDER BY e.last_seen DESC
            """) as cur:
                endpoints = [dict(r) for r in await cur.fetchall()]
        return templates.TemplateResponse("endpoints.html", {"request": request, "user": user, "endpoints": endpoints})

    @app.post("/api/endpoints/register")
    async def register_endpoint(request: Request):
        _rate_limit(f"register:{request.client.host}", max_requests=5, window_seconds=300)
        data = await request.json()
        hostname = data.get("hostname", "unknown")[:128]
        ip = data.get("ip_address", request.client.host)
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            # Check if already registered by hostname+ip
            async with db.execute(
                "SELECT id, agent_token, approved FROM endpoints WHERE hostname=? AND ip_address=?",
                (hostname, ip)
            ) as cur:
                existing = await cur.fetchone()

            if existing:
                # Re-registering — update and return same token
                await db.execute("""
                    UPDATE endpoints SET os_version=?, agent_version=?, status='pending',
                    last_seen=datetime('now') WHERE id=?
                """, (data.get("os_version"), data.get("agent_version"), existing["id"]))
                await db.commit()
                return JSONResponse({
                    "token": existing["agent_token"],
                    "endpoint_id": existing["id"],
                    "approved": bool(existing["approved"])
                })

            # New registration — create with approved=0 (pending)
            token = create_agent_token()
            await db.execute("""
                INSERT INTO endpoints
                    (hostname, ip_address, os_type, os_version, agent_version, agent_token, status, approved, last_seen)
                VALUES (?,?,?,?,?,?,'pending',0,datetime('now'))
            """, (hostname, ip, data.get("os_type"), data.get("os_version"), data.get("agent_version"), token))
            await db.commit()
            async with db.execute("SELECT id FROM endpoints WHERE agent_token=?", (token,)) as cur:
                row = await cur.fetchone()
        return JSONResponse({"token": token, "endpoint_id": row["id"], "approved": False})

    @app.post("/api/endpoints/{endpoint_id}/adopt")
    async def adopt_endpoint(endpoint_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute(
                "UPDATE endpoints SET approved=1, status='offline' WHERE id=?", (endpoint_id,)
            )
            await db.commit()
        return JSONResponse({"status": "adopted"})

    @app.post("/api/endpoints/{endpoint_id}/reject")
    async def reject_endpoint(endpoint_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM endpoints WHERE id=? AND approved=0", (endpoint_id,))
            await db.commit()
        return JSONResponse({"status": "rejected"})

    @app.get("/api/endpoints/{endpoint_id}/status")
    async def endpoint_status(endpoint_id: int, request: Request):
        token = request.headers.get("X-Agent-Token", "")
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute(
                "SELECT approved, status FROM endpoints WHERE id=? AND agent_token=?",
                (endpoint_id, token)
            ) as cur:
                row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404)
        return JSONResponse({"approved": bool(row["approved"]), "status": row["status"]})

    @app.post("/api/endpoints/heartbeat")
    async def heartbeat(request: Request):
        token = request.headers.get("X-Agent-Token", "")
        if not token:
            raise HTTPException(status_code=401)
        data = await request.json()
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute(
                "SELECT id, approved FROM endpoints WHERE agent_token=?", (token,)
            ) as cur:
                ep = await cur.fetchone()
            if not ep:
                raise HTTPException(status_code=403)
            if not ep["approved"]:
                return JSONResponse({"status": "pending_approval"})
            await db.execute("""
                UPDATE endpoints SET status='online', last_seen=datetime('now'),
                ip_address=? WHERE agent_token=?
            """, (data.get("ip_address"), token))
            await db.commit()
        return JSONResponse({"status": "ok"})

    @app.delete("/api/endpoints/{endpoint_id}")
    async def delete_endpoint(endpoint_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM endpoints WHERE id=?", (endpoint_id,))
            await db.commit()
        return JSONResponse({"status": "deleted"})

    # ─── Threats ─────────────────────────────────────────────────────────────

    @app.get("/threats", response_class=HTMLResponse)
    async def threats_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("""
                SELECT t.*, e.hostname FROM threats t
                LEFT JOIN endpoints e ON t.endpoint_id=e.id
                ORDER BY t.detected_at DESC LIMIT 500
            """) as cur:
                threats = [dict(r) for r in await cur.fetchall()]
        return templates.TemplateResponse("threats.html", {"request": request, "user": user, "threats": threats})

    @app.post("/api/threats/report")
    async def report_threat(request: Request):
        token = request.headers.get("X-Agent-Token", "")
        if not token:
            raise HTTPException(status_code=401)
        data = await request.json()
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute(
                "SELECT id, hostname FROM endpoints WHERE agent_token=? AND approved=1", (token,)
            ) as cur:
                endpoint = await cur.fetchone()
            if not endpoint:
                raise HTTPException(status_code=403)
            await db.execute("""
                INSERT INTO threats (endpoint_id, threat_type, severity, name, description,
                    file_path, file_hash, process_name, process_pid, network_ip, network_domain, action_taken)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (endpoint["id"], data.get("threat_type"), data.get("severity", "medium"),
                  data.get("name"), data.get("description"), data.get("file_path"),
                  data.get("file_hash"), data.get("process_name"), data.get("process_pid"),
                  data.get("network_ip"), data.get("network_domain"), data.get("action_taken", "detected")))
            await db.commit()

        # Broadcast real-time alert to all connected browsers
        add_scan_event({
            "type": "threat_detected",
            "threat_type": data.get("threat_type", "malware"),
            "severity": data.get("severity", "medium"),
            "name": data.get("name", "Unknown Threat"),
            "description": data.get("description", ""),
            "file_path": data.get("file_path", ""),
            "process_name": data.get("process_name", ""),
            "endpoint": endpoint["hostname"],
            "action_taken": data.get("action_taken", "detected"),
        })
        return JSONResponse({"status": "recorded"})

    @app.post("/api/threats/{threat_id}/resolve")
    async def resolve_threat(threat_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("""
                UPDATE threats SET status='resolved', resolved_at=datetime('now') WHERE id=?
            """, (threat_id,))
            await db.commit()
        return JSONResponse({"status": "resolved"})

    @app.post("/api/threats/{threat_id}/false_positive")
    async def mark_false_positive(threat_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("UPDATE threats SET false_positive=1, status='resolved' WHERE id=?", (threat_id,))
            await db.commit()
        return JSONResponse({"status": "ok"})

    # ─── Quarantine ──────────────────────────────────────────────────────────

    @app.get("/quarantine", response_class=HTMLResponse)
    async def quarantine_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("""
                SELECT q.*, e.hostname, t.name as threat_name FROM quarantine q
                LEFT JOIN endpoints e ON q.endpoint_id=e.id
                LEFT JOIN threats t ON q.threat_id=t.id
                ORDER BY q.quarantined_at DESC
            """) as cur:
                items = [dict(r) for r in await cur.fetchall()]
        return templates.TemplateResponse("quarantine.html", {"request": request, "user": user, "items": items})

    @app.post("/api/quarantine/add")
    async def add_quarantine(request: Request):
        token = request.headers.get("X-Agent-Token", "")
        data = await request.json()
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute(
                "SELECT id FROM endpoints WHERE agent_token=? AND approved=1", (token,)
            ) as cur:
                ep = await cur.fetchone()
            if not ep:
                raise HTTPException(status_code=403)
            orig_path = _safe_path(data.get("original_path"))
            quar_path = _safe_path(data.get("quarantine_path"))
            await db.execute("""
                INSERT INTO quarantine (endpoint_id, threat_id, original_path, quarantine_path, file_hash, file_size)
                VALUES (?,?,?,?,?,?)
            """, (ep["id"], data.get("threat_id"), orig_path,
                  quar_path, data.get("file_hash"), data.get("file_size")))
            await db.commit()
        return JSONResponse({"status": "quarantined"})

    @app.post("/api/quarantine/{item_id}/restore")
    async def restore_quarantine(item_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("UPDATE quarantine SET restored=1, restored_at=datetime('now') WHERE id=?", (item_id,))
            await db.commit()
        return JSONResponse({"status": "restored"})

    @app.delete("/api/quarantine/{item_id}")
    async def delete_quarantine(item_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM quarantine WHERE id=?", (item_id,))
            await db.commit()
        return JSONResponse({"status": "deleted"})

    # ─── YARA Rules ──────────────────────────────────────────────────────────

    @app.get("/yara", response_class=HTMLResponse)
    async def yara_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("SELECT * FROM yara_rules ORDER BY category, name") as cur:
                rules = [dict(r) for r in await cur.fetchall()]
        return templates.TemplateResponse("yara_rules.html", {"request": request, "user": user, "rules": rules})

    @app.post("/api/yara/add")
    async def add_yara_rule(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        db = await get_db()
        async with db:
            await db.execute("""
                INSERT INTO yara_rules (name, category, description, rule_content, enabled)
                VALUES (?,?,?,?,1)
            """, (data["name"], data.get("category", "custom"), data.get("description"), data["rule_content"]))
            await db.commit()
        return JSONResponse({"status": "added"})

    @app.put("/api/yara/{rule_id}")
    async def update_yara_rule(rule_id: int, request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        db = await get_db()
        async with db:
            await db.execute("""
                UPDATE yara_rules SET name=?, category=?, description=?, rule_content=?,
                enabled=?, updated_at=datetime('now') WHERE id=?
            """, (data["name"], data.get("category", "custom"), data.get("description"),
                  data["rule_content"], data.get("enabled", 1), rule_id))
            await db.commit()
        return JSONResponse({"status": "updated"})

    @app.delete("/api/yara/{rule_id}")
    async def delete_yara_rule(rule_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM yara_rules WHERE id=?", (rule_id,))
            await db.commit()
        return JSONResponse({"status": "deleted"})

    @app.get("/api/yara/export")
    async def export_yara_rules(request: Request):
        # Accept both admin JWT and agent X-Agent-Token
        agent_token = request.headers.get("X-Agent-Token", "")
        if not agent_token:
            try:
                await require_api_auth(request)
            except HTTPException:
                raise HTTPException(status_code=401, detail="Unauthorized")
        else:
            db_check = await get_db()
            async with db_check:
                db_check.row_factory = __import__('aiosqlite').Row
                async with db_check.execute(
                    "SELECT id FROM endpoints WHERE agent_token=? AND approved=1", (agent_token,)
                ) as cur:
                    if not await cur.fetchone():
                        raise HTTPException(status_code=403)

        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("SELECT * FROM yara_rules WHERE enabled=1") as cur:
                rules = [dict(r) for r in await cur.fetchall()]
        combined = "\n\n".join(r["rule_content"] for r in rules)
        return HTMLResponse(content=combined, media_type="text/plain")

    # ─── IoC Feeds ───────────────────────────────────────────────────────────

    @app.get("/ioc", response_class=HTMLResponse)
    async def ioc_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("SELECT * FROM ioc_feed_config ORDER BY name") as cur:
                feeds = [dict(r) for r in await cur.fetchall()]
            async with db.execute("SELECT COUNT(*) as c FROM ioc_entries WHERE ioc_type='ip'") as cur:
                ip_count = (await cur.fetchone())["c"]
            async with db.execute("SELECT COUNT(*) as c FROM ioc_entries WHERE ioc_type='domain'") as cur:
                domain_count = (await cur.fetchone())["c"]
            async with db.execute("SELECT COUNT(*) as c FROM ioc_entries WHERE ioc_type='hash'") as cur:
                hash_count = (await cur.fetchone())["c"]
            async with db.execute("SELECT * FROM ioc_entries ORDER BY added_at DESC LIMIT 100") as cur:
                recent = [dict(r) for r in await cur.fetchall()]
        return templates.TemplateResponse("ioc_feeds.html", {
            "request": request, "user": user, "feeds": feeds,
            "ip_count": ip_count, "domain_count": domain_count,
            "hash_count": hash_count, "recent": recent
        })

    @app.post("/api/ioc/feeds/update")
    async def update_ioc_feeds(user=Depends(require_api_auth)):
        from core.ioc_feeds import update_all_feeds
        asyncio.create_task(update_all_feeds())
        return JSONResponse({"status": "started"})

    @app.post("/api/ioc/check")
    async def check_ioc(request: Request):
        token = request.headers.get("X-Agent-Token", "")
        if not token:
            raise HTTPException(status_code=401)
        # Validate token belongs to an approved endpoint
        db_check = await get_db()
        async with db_check:
            db_check.row_factory = __import__('aiosqlite').Row
            async with db_check.execute(
                "SELECT id FROM endpoints WHERE agent_token=? AND approved=1", (token,)
            ) as cur:
                if not await cur.fetchone():
                    raise HTTPException(status_code=403)
        data = await request.json()
        value = data.get("value", "").strip().lower()
        ioc_type = data.get("type", "")
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute(
                "SELECT * FROM ioc_entries WHERE ioc_type=? AND value=?", (ioc_type, value)
            ) as cur:
                match = await cur.fetchone()
        if match:
            return JSONResponse({"found": True, "threat": dict(match)})
        return JSONResponse({"found": False})

    # ─── Settings ────────────────────────────────────────────────────────────

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("SELECT * FROM settings") as cur:
                rows = await cur.fetchall()
                settings = {r["key"]: r["value"] for r in rows}
            async with db.execute("SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at") as cur:
                users = [dict(r) for r in await cur.fetchall()]
        return templates.TemplateResponse("settings.html", {
            "request": request, "user": user, "settings": settings, "users": users
        })

    @app.post("/api/settings")
    async def save_settings(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        db = await get_db()
        async with db:
            for key, value in data.items():
                await db.execute("""
                    INSERT INTO settings (key, value, updated_at) VALUES (?,?,datetime('now'))
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """, (key, str(value)))
            await db.commit()
        return JSONResponse({"status": "saved"})

    @app.post("/api/users/add")
    async def add_user(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        db = await get_db()
        async with db:
            await db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (data["username"], hash_password(data["password"]), data.get("role", "admin"))
            )
            await db.commit()
        return JSONResponse({"status": "created"})

    @app.delete("/api/users/{user_id}")
    async def delete_user(user_id: int, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM users WHERE id=?", (user_id,))
            await db.commit()
        return JSONResponse({"status": "deleted"})

    # ─── Scan Console ────────────────────────────────────────────────────────

    @app.get("/scan", response_class=HTMLResponse)
    async def scan_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("""
                SELECT s.*, e.hostname FROM scan_jobs s
                LEFT JOIN endpoints e ON s.endpoint_id=e.id
                ORDER BY s.created_at DESC LIMIT 50
            """) as cur:
                jobs = [dict(r) for r in await cur.fetchall()]
            async with db.execute("""
                SELECT * FROM endpoints WHERE approved=1 ORDER BY hostname
            """) as cur:
                endpoints = [dict(r) for r in await cur.fetchall()]
        return templates.TemplateResponse("scan.html", {
            "request": request, "user": user,
            "scan_jobs": jobs, "endpoints": endpoints
        })

    @app.post("/api/scan/start")
    async def start_scan(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        endpoint_id = data.get("endpoint_id")
        scan_type   = data.get("scan_type", "quick")
        target_path = data.get("target_path", "/")

        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row

            # Collect target endpoints
            if endpoint_id:
                async with db.execute(
                    "SELECT * FROM endpoints WHERE id=? AND approved=1 AND status='online'",
                    (endpoint_id,)
                ) as cur:
                    endpoints = [dict(r) for r in await cur.fetchall()]
            else:
                async with db.execute(
                    "SELECT * FROM endpoints WHERE approved=1 AND status='online'"
                ) as cur:
                    endpoints = [dict(r) for r in await cur.fetchall()]

            if not endpoints:
                return JSONResponse({"status": "error", "message": "No online endpoints found"})

            job_ids = []
            for ep in endpoints:
                job_id = queue_scan(ep["id"], scan_type, target_path)
                await db.execute("""
                    INSERT INTO scan_jobs (endpoint_id, scan_type, target_path, status, created_at)
                    VALUES (?,?,?,'queued',datetime('now'))
                """, (ep["id"], scan_type, target_path))
                job_ids.append(job_id)
                add_scan_event({
                    "type": "scan_start",
                    "endpoint": ep["hostname"],
                    "endpoint_id": ep["id"],
                    "scan_type": scan_type,
                    "target_path": target_path,
                    "job_id": job_id
                })
            await db.commit()

        return JSONResponse({
            "status": "ok",
            "job_id": job_ids[0] if len(job_ids) == 1 else job_ids,
            "endpoints": len(endpoints)
        })

    @app.get("/api/scan/jobs")
    async def get_scan_jobs(limit: int = 20, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("""
                SELECT s.*, e.hostname,
                    CASE WHEN s.completed_at IS NOT NULL AND s.started_at IS NOT NULL
                    THEN ROUND((julianday(s.completed_at)-julianday(s.started_at))*86400,1)||'s'
                    ELSE NULL END as duration
                FROM scan_jobs s
                LEFT JOIN endpoints e ON s.endpoint_id=e.id
                ORDER BY s.created_at DESC LIMIT ?
            """, (limit,)) as cur:
                jobs = [dict(r) for r in await cur.fetchall()]
        return JSONResponse(jobs)

    @app.get("/api/scan/events")
    async def get_scan_events_api(limit: int = 100, user=Depends(require_api_auth)):
        return JSONResponse(get_scan_events(limit))

    # Agent picks up pending scan commands
    @app.get("/api/scan/commands")
    async def get_commands(request: Request):
        token = request.headers.get("X-Agent-Token", "")
        if not token:
            raise HTTPException(status_code=401)
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute(
                "SELECT id FROM endpoints WHERE agent_token=? AND approved=1", (token,)
            ) as cur:
                ep = await cur.fetchone()
        if not ep:
            raise HTTPException(status_code=403)
        cmds = get_pending_commands(ep["id"])
        return JSONResponse({"commands": cmds})

    # Agent reports scan progress/results
    @app.post("/api/scan/report")
    async def report_scan(request: Request):
        token = request.headers.get("X-Agent-Token", "")
        if not token:
            raise HTTPException(status_code=401)
        data = await request.json()
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute(
                "SELECT id, hostname FROM endpoints WHERE agent_token=? AND approved=1", (token,)
            ) as cur:
                ep = await cur.fetchone()
        if not ep:
            raise HTTPException(status_code=403)

        event_type = data.get("type", "scan_progress")
        event = {**data, "endpoint": ep["hostname"], "endpoint_id": ep["id"]}
        add_scan_event(event)

        if event_type == "scan_complete":
            db2 = await get_db()
            async with db2:
                await db2.execute("""
                    UPDATE scan_jobs SET status='completed',
                        started_at=?, completed_at=datetime('now'),
                        files_scanned=?, threats_found=?
                    WHERE endpoint_id=? AND status='queued'
                    ORDER BY created_at DESC LIMIT 1
                """, (data.get("started_at"), data.get("files_scanned", 0),
                      data.get("threats_found", 0), ep["id"]))
                await db2.commit()

        return JSONResponse({"status": "ok"})

    # ─── WebSocket — real-time scan feed ─────────────────────────────────────

    @app.websocket("/ws/scan")
    async def ws_scan(websocket: WebSocket, token: str = ""):
        # Auth via cookie or query param
        cookie_token = websocket.cookies.get("aegisedr_token", "")
        auth_token = token or cookie_token
        if not auth_token:
            await websocket.close(code=1008)
            return
        try:
            from web.auth import decode_token
            decode_token(auth_token)
        except Exception:
            await websocket.close(code=1008)
            return

        await websocket.accept()
        register_ws(websocket)

        # Send last 20 events on connect
        for ev in get_scan_events(20):
            try:
                await websocket.send_text(json.dumps(ev))
            except Exception:
                break

        try:
            while True:
                await websocket.receive_text()  # keep alive (ping)
        except WebSocketDisconnect:
            pass
        finally:
            unregister_ws(websocket)

    # ─── Agent file serving ──────────────────────────────────────────────────

    @app.get("/agent/agent_linux.py")
    async def serve_linux_agent():
        import aiofiles
        path = os.path.join(os.path.dirname(__file__), "..", "agent", "agent_linux.py")
        async with aiofiles.open(path, "r") as f:
            content = await f.read()
        return HTMLResponse(content=content, media_type="text/plain")

    @app.get("/agent/agent_windows.py")
    async def serve_windows_agent():
        import aiofiles
        path = os.path.join(os.path.dirname(__file__), "..", "agent", "agent_windows.py")
        async with aiofiles.open(path, "r") as f:
            content = await f.read()
        return HTMLResponse(content=content, media_type="text/plain")

    @app.get("/agent/install.sh")
    async def serve_linux_install():
        import aiofiles
        path = os.path.join(os.path.dirname(__file__), "..", "agent", "install_linux.sh")
        async with aiofiles.open(path, "r") as f:
            content = await f.read()
        return HTMLResponse(content=content, media_type="text/plain")

    @app.get("/agent/install.ps1")
    async def serve_windows_install():
        import aiofiles
        path = os.path.join(os.path.dirname(__file__), "..", "agent", "install_windows.ps1")
        async with aiofiles.open(path, "r") as f:
            content = await f.read()
        return HTMLResponse(content=content, media_type="text/plain")

    @app.get("/agent/AegisEDR-Agent-1.0.0-x64.msi")
    async def serve_windows_msi():
        from fastapi.responses import FileResponse
        path = os.path.join(os.path.dirname(__file__), "..", "downloads", "AegisEDR-Agent-1.0.0-x64.msi")
        if not os.path.isfile(path):
            raise HTTPException(status_code=404, detail="MSI not found on server")
        return FileResponse(path, media_type="application/octet-stream",
                            filename="AegisEDR-Agent-1.0.0-x64.msi")

    # ─── API Stats ───────────────────────────────────────────────────────────

    @app.get("/api/stats")
    async def get_stats(user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            stats = {}
            for table in ["endpoints", "threats", "quarantine", "ioc_entries", "yara_rules"]:
                async with db.execute(f"SELECT COUNT(*) as c FROM {table}") as cur:
                    stats[table] = (await cur.fetchone())["c"]
            async with db.execute("SELECT severity, COUNT(*) as c FROM threats WHERE status='active' GROUP BY severity") as cur:
                stats["threats_by_severity"] = {r["severity"]: r["c"] for r in await cur.fetchall()}
        return JSONResponse(stats)

import asyncio
import os
