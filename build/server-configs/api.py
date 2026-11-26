import asyncio
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, Form, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from config import ALLOWED_SETTINGS, TLS_CERT_PATH
from core.database import get_db, hash_agent_token
from core.scanner import add_scan_event, get_scan_events, register_ws, unregister_ws
from web.auth import (
    authenticate_user, create_token, require_auth, require_api_auth,
    hash_password, create_agent_token, cookie_secure, user_count,
    read_setup_token, consume_setup_token, validate_new_password,
    endpoint_from_token, decode_token,
)
from web.security import client_ip, rate_limit, audit

templates = Jinja2Templates(directory="web/templates")


def render(request: Request, name: str, context: dict, status_code: int = 200):
    """Support Starlette 0.x (name first) and 1.x (request first)."""
    import starlette
    major = int(starlette.__version__.split(".")[0])
    if major >= 1:
        return templates.TemplateResponse(request, name, context, status_code=status_code)
    return templates.TemplateResponse(name, context, status_code=status_code)

_USERNAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,31}$")
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_BOOL_SETTINGS = {
    "auto_quarantine", "auto_block_ransomware", "virustotal_enabled", "ioc_auto_update",
}
_INT_SETTINGS = {"ioc_update_interval_hours", "agent_heartbeat_interval", "retention_days"}
_POLICY_KEYS = ("auto_quarantine", "auto_block_ransomware", "agent_heartbeat_interval")


def _clip(value, limit: int):
    if value is None:
        return None
    text = str(value).replace("\x00", "")
    return text[:limit]


def _clean_hostname(value) -> str:
    text = _clip(value, 128) or "unknown"
    return "".join(ch for ch in text if ch.isprintable()).strip() or "unknown"


def tls_cert_sha256() -> str | None:
    if not os.path.isfile(TLS_CERT_PATH):
        return None
    digest = hashlib.sha256()
    with open(TLS_CERT_PATH, "rb") as handle:
        digest.update(handle.read())
    return digest.hexdigest()


def _validate_yara(source: str):
    if not source or len(source) > 256_000:
        raise HTTPException(status_code=400, detail="YARA rule is empty or too large")
    try:
        import yara
    except ImportError:
        return
    try:
        yara.compile(source=source)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"YARA rule rejected: {exc}") from exc


async def _policy() -> dict:
    db = await get_db()
    async with db:
        policy = {}
        for key in _POLICY_KEYS:
            async with db.execute("SELECT value FROM settings WHERE key=?", (key,)) as cur:
                row = await cur.fetchone()
                policy[key] = row[0] if row else "0"
    return policy


async def _require_agent(request: Request, approved_only: bool = True) -> dict:
    token = request.headers.get("X-Agent-Token", "")
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    endpoint = await endpoint_from_token(token, approved_only=approved_only)
    if not endpoint:
        raise HTTPException(status_code=403, detail="Unknown or unapproved agent")
    return endpoint


async def claim_commands(endpoint_id: int) -> list:
    db = await get_db()
    async with db:
        db.row_factory = __import__("aiosqlite").Row
        await db.execute("BEGIN IMMEDIATE")
        async with db.execute(
            """
            SELECT id, command, payload FROM agent_commands
            WHERE endpoint_id=? AND status='queued'
            ORDER BY id LIMIT 20
            """,
            (endpoint_id,),
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        if rows:
            ids = [row["id"] for row in rows]
            marks = ",".join("?" * len(ids))
            await db.execute(
                f"""
                UPDATE agent_commands
                SET status='running', started_at=datetime('now')
                WHERE status='queued' AND id IN ({marks})
                """,
                ids,
            )
        await db.commit()
    commands = []
    for row in rows:
        try:
            payload = json.loads(row["payload"] or "{}")
        except json.JSONDecodeError:
            payload = {}
        commands.append({
            "id": row["id"],
            "command": row["command"],
            "type": row["command"],
            "payload": payload,
            "scan_type": payload.get("scan_type"),
            "target_path": payload.get("target_path"),
            "scan_job_id": payload.get("scan_job_id"),
        })
    return commands


def register_routes(app: FastAPI):

    # ─── First-run setup ────────────────────────────────────────────────────

    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request):
        if await user_count() > 0:
            return RedirectResponse("/login", status_code=302)
        return render(request, "setup.html", {"request": request, "error": None})

    @app.post("/setup", response_class=HTMLResponse)
    async def setup_submit(
        request: Request,
        setup_token: str = Form(...),
        username: str = Form(...),
        password: str = Form(...),
    ):
        if await user_count() > 0:
            return RedirectResponse("/login", status_code=302)
        ip = client_ip(request)
        await rate_limit(f"setup:{ip}", max_requests=5, window_seconds=300)
        expected = read_setup_token()
        presented = setup_token.strip()
        token_ok = bool(expected) and len(presented) == len(expected) and secrets.compare_digest(presented, expected)
        if not token_ok:
            return render(request, 
                "setup.html",
                {"request": request, "error": "Invalid setup token"},
                status_code=401,
            )
        if not _USERNAME.match(username):
            return render(request, 
                "setup.html",
                {"request": request, "error": "Username must be 3-32 characters: a letter, then letters, digits or underscore"},
                status_code=400,
            )
        problem = validate_new_password(password)
        if problem:
            return render(request, 
                "setup.html", {"request": request, "error": problem}, status_code=400,
            )
        db = await get_db()
        async with db:
            await db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, hash_password(password), "admin"),
            )
            await db.commit()
        consume_setup_token()
        await audit(username, "setup_admin", "initial administrator created", ip)
        return RedirectResponse("/login", status_code=302)

    # ─── Auth ────────────────────────────────────────────────────────────────

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if await user_count() == 0:
            return RedirectResponse("/setup", status_code=302)
        return render(request, "login.html", {"request": request, "error": None})

    @app.post("/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...)):
        ip = client_ip(request)
        await rate_limit(f"login:{ip}", max_requests=10, window_seconds=60)
        user = await authenticate_user(username, password)
        if not user:
            return render(request, 
                "login.html",
                {"request": request, "error": "Invalid credentials"},
                status_code=401,
            )
        token = create_token(user["username"], user["role"])
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(
            "aegisedr_token", token,
            httponly=True, secure=cookie_secure(request), samesite="lax", max_age=28800,
        )
        await audit(username, "login", None, ip)
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
            db.row_factory = __import__("aiosqlite").Row
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
                SELECT id, hostname, ip_address, os_type, os_version, agent_version,
                       status, approved, last_seen, registered_at, protection_enabled, tags
                FROM endpoints ORDER BY approved ASC, last_seen DESC LIMIT 10
            """) as cur:
                endpoints = [dict(r) for r in await cur.fetchall()]
            async with db.execute("SELECT COUNT(*) as c FROM endpoints WHERE approved=0") as cur:
                pending_count = (await cur.fetchone())["c"]

        return render(request, "dashboard.html", {
            "request": request, "user": user,
            "total_endpoints": total_endpoints, "online_endpoints": online_endpoints,
            "active_threats": active_threats, "critical_threats": critical_threats,
            "quarantine_count": quarantine_count, "ioc_count": ioc_count,
            "recent_threats": recent_threats, "endpoints": endpoints,
            "pending_count": pending_count,
        })

    # ─── Deploy / enrollment ─────────────────────────────────────────────────

    @app.get("/deploy", response_class=HTMLResponse)
    async def deploy_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        console_url = str(request.base_url).rstrip("/")
        msi_candidates = [
            os.path.join(os.path.dirname(__file__), "..", "downloads", "AegisEDR-Agent-1.0.0-x64.msi"),
            os.path.join(os.path.dirname(__file__), "..", "dist", "AegisEDR-Agent-1.0.0-x64.msi"),
        ]
        msi_path = next((p for p in msi_candidates if os.path.isfile(p)), None)
        msi_size = ""
        if msi_path:
            msi_size = f"{os.path.getsize(msi_path) / 1024 / 1024:.1f} MB"
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("""
                SELECT id, label, max_uses, uses_remaining, created_at, expires_at, revoked, created_by
                FROM enrollment_codes ORDER BY id DESC LIMIT 20
            """) as cur:
                codes = [dict(r) for r in await cur.fetchall()]
        return render(request, "deploy.html", {
            "request": request, "user": user,
            "console_url": console_url,
            "msi_available": msi_path is not None,
            "msi_size": msi_size,
            "ca_fingerprint": tls_cert_sha256(),
            "enrollment_codes": codes,
        })

    @app.post("/api/enrollment/codes")
    async def create_enrollment_code(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        try:
            max_uses = int(data.get("max_uses", 1))
            ttl_hours = int(data.get("ttl_hours", 24))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="max_uses and ttl_hours must be integers")
        if not 1 <= max_uses <= 500 or not 1 <= ttl_hours <= 24 * 30:
            raise HTTPException(status_code=400, detail="max_uses 1-500, ttl_hours 1-720")
        label = _clip(data.get("label") or "agent", 80)
        code = secrets.token_urlsafe(18)
        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).strftime("%Y-%m-%d %H:%M:%S")
        db = await get_db()
        async with db:
            await db.execute(
                """
                INSERT INTO enrollment_codes
                    (code_hash, label, created_by, max_uses, uses_remaining, expires_at)
                VALUES (?,?,?,?,?,?)
                """,
                (hash_agent_token(code), label, user.get("sub"), max_uses, max_uses, expires),
            )
            await db.commit()
        await audit(user.get("sub"), "enrollment_code", f"label={label} uses={max_uses}", client_ip(request))
        return JSONResponse({
            "code": code,
            "label": label,
            "max_uses": max_uses,
            "expires_at": expires,
        })

    @app.post("/api/enrollment/codes/{code_id}/revoke")
    async def revoke_enrollment_code(code_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("UPDATE enrollment_codes SET revoked=1 WHERE id=?", (code_id,))
            await db.commit()
        await audit(user.get("sub"), "enrollment_revoke", f"id={code_id}", client_ip(request))
        return JSONResponse({"status": "revoked"})

    # ─── Endpoints ───────────────────────────────────────────────────────────

    @app.get("/endpoints", response_class=HTMLResponse)
    async def endpoints_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("""
                SELECT e.id, e.hostname, e.ip_address, e.os_type, e.os_version, e.agent_version,
                       e.status, e.approved, e.last_seen, e.registered_at, e.protection_enabled, e.tags,
                    (SELECT COUNT(*) FROM threats WHERE endpoint_id=e.id AND status='active') as active_threats
                FROM endpoints e ORDER BY e.last_seen DESC
            """) as cur:
                endpoints = [dict(r) for r in await cur.fetchall()]
        return render(request, "endpoints.html", {"request": request, "user": user, "endpoints": endpoints})

    @app.post("/api/endpoints/register")
    async def register_endpoint(request: Request):
        ip = client_ip(request)
        await rate_limit(f"register:{ip}", max_requests=5, window_seconds=300)
        data = await request.json()
        hostname = _clean_hostname(data.get("hostname"))
        presented = request.headers.get("X-Agent-Token", "")

        if presented:
            existing = await endpoint_from_token(presented, approved_only=False)
            if not existing:
                raise HTTPException(status_code=403, detail="Unknown agent token")
            new_status = "online" if existing["approved"] else "pending"
            db = await get_db()
            async with db:
                await db.execute(
                    """
                    UPDATE endpoints
                    SET hostname=?, os_type=?, os_version=?, agent_version=?,
                        status=?, ip_address=?, last_seen=datetime('now')
                    WHERE id=?
                    """,
                    (
                        hostname,
                        _clip(data.get("os_type"), 40),
                        _clip(data.get("os_version"), 80),
                        _clip(data.get("agent_version"), 40),
                        new_status,
                        ip,
                        existing["id"],
                    ),
                )
                await db.commit()
            return JSONResponse({
                "endpoint_id": existing["id"],
                "approved": bool(existing["approved"]),
                "status": new_status,
            })

        code = (data.get("enrollment_code") or "").strip()
        if not code:
            raise HTTPException(status_code=401, detail="Enrollment code required")
        code_hash = hash_agent_token(code)
        token = create_agent_token()
        db = await get_db()
        async with db:
            cur = await db.execute(
                """
                UPDATE enrollment_codes
                SET uses_remaining = uses_remaining - 1
                WHERE code_hash=? AND revoked=0 AND uses_remaining>0
                  AND (expires_at IS NULL OR expires_at > datetime('now'))
                """,
                (code_hash,),
            )
            if cur.rowcount != 1:
                await db.rollback()
                raise HTTPException(status_code=403, detail="Invalid or exhausted enrollment code")
            cur = await db.execute(
                """
                INSERT INTO endpoints
                    (hostname, ip_address, os_type, os_version, agent_version, agent_token_hash, status, approved, last_seen)
                VALUES (?,?,?,?,?,?,'pending',0,datetime('now'))
                """,
                (
                    hostname, ip,
                    _clip(data.get("os_type"), 40),
                    _clip(data.get("os_version"), 80),
                    _clip(data.get("agent_version"), 40),
                    hash_agent_token(token),
                ),
            )
            endpoint_id = cur.lastrowid
            await db.commit()
        return JSONResponse({"token": token, "endpoint_id": endpoint_id, "approved": False})

    @app.post("/api/endpoints/{endpoint_id}/adopt")
    async def adopt_endpoint(endpoint_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute(
                "UPDATE endpoints SET approved=1, status='offline' WHERE id=?",
                (endpoint_id,),
            )
            await db.commit()
        await audit(user.get("sub"), "adopt", f"endpoint={endpoint_id}", client_ip(request))
        return JSONResponse({"status": "adopted"})

    @app.post("/api/endpoints/{endpoint_id}/reject")
    async def reject_endpoint(endpoint_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM endpoints WHERE id=? AND approved=0", (endpoint_id,))
            await db.commit()
        await audit(user.get("sub"), "reject", f"endpoint={endpoint_id}", client_ip(request))
        return JSONResponse({"status": "rejected"})

    @app.get("/api/endpoints/{endpoint_id}/status")
    async def endpoint_status(endpoint_id: int, request: Request):
        endpoint = await _require_agent(request, approved_only=False)
        if endpoint["id"] != endpoint_id:
            raise HTTPException(status_code=404)
        return JSONResponse({"approved": bool(endpoint["approved"]), "status": endpoint["status"]})

    @app.post("/api/endpoints/heartbeat")
    async def heartbeat(request: Request):
        endpoint = await _require_agent(request, approved_only=False)
        if not endpoint["approved"]:
            return JSONResponse({"status": "pending_approval"})
        db = await get_db()
        async with db:
            await db.execute(
                """
                UPDATE endpoints SET status='online', last_seen=datetime('now'), ip_address=?
                WHERE id=?
                """,
                (client_ip(request), endpoint["id"]),
            )
            await db.commit()
        return JSONResponse({"status": "ok", "policy": await _policy()})

    @app.delete("/api/endpoints/{endpoint_id}")
    async def delete_endpoint(endpoint_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM endpoints WHERE id=?", (endpoint_id,))
            await db.execute("DELETE FROM agent_commands WHERE endpoint_id=?", (endpoint_id,))
            await db.commit()
        await audit(user.get("sub"), "delete_endpoint", f"endpoint={endpoint_id}", client_ip(request))
        return JSONResponse({"status": "deleted"})

    # ─── Threats ─────────────────────────────────────────────────────────────

    @app.get("/threats", response_class=HTMLResponse)
    async def threats_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("""
                SELECT t.*, e.hostname FROM threats t
                LEFT JOIN endpoints e ON t.endpoint_id=e.id
                ORDER BY t.detected_at DESC LIMIT 500
            """) as cur:
                threats = [dict(r) for r in await cur.fetchall()]
        return render(request, "threats.html", {"request": request, "user": user, "threats": threats})

    @app.post("/api/threats/report")
    async def report_threat(request: Request):
        endpoint = await _require_agent(request, approved_only=True)
        await rate_limit(f"threat:{endpoint['id']}", max_requests=60, window_seconds=60)
        data = await request.json()
        severity = (data.get("severity") or "medium").lower()
        if severity not in _SEVERITIES:
            severity = "medium"
        db = await get_db()
        async with db:
            await db.execute(
                """
                INSERT INTO threats (endpoint_id, threat_type, severity, name, description,
                    file_path, file_hash, process_name, process_pid, network_ip, network_domain, action_taken)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    endpoint["id"],
                    _clip(data.get("threat_type"), 40) or "malware",
                    severity,
                    _clip(data.get("name"), 200) or "Unknown",
                    _clip(data.get("description"), 2000),
                    _clip(data.get("file_path"), 1024),
                    _clip(data.get("file_hash"), 128),
                    _clip(data.get("process_name"), 200),
                    data.get("process_pid") if isinstance(data.get("process_pid"), int) else None,
                    _clip(data.get("network_ip"), 64),
                    _clip(data.get("network_domain"), 253),
                    _clip(data.get("action_taken"), 40) or "detected",
                ),
            )
            await db.commit()
        add_scan_event({
            "type": "threat_detected",
            "threat_type": _clip(data.get("threat_type"), 40) or "malware",
            "severity": severity,
            "name": _clip(data.get("name"), 200) or "Unknown Threat",
            "description": _clip(data.get("description"), 500) or "",
            "file_path": _clip(data.get("file_path"), 1024) or "",
            "process_name": _clip(data.get("process_name"), 200) or "",
            "endpoint": endpoint["hostname"],
            "action_taken": _clip(data.get("action_taken"), 40) or "detected",
        })
        return JSONResponse({"status": "recorded"})

    @app.post("/api/threats/{threat_id}/resolve")
    async def resolve_threat(threat_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute(
                "UPDATE threats SET status='resolved', resolved_at=datetime('now') WHERE id=?",
                (threat_id,),
            )
            await db.commit()
        await audit(user.get("sub"), "resolve_threat", f"id={threat_id}", client_ip(request))
        return JSONResponse({"status": "resolved"})

    @app.post("/api/threats/{threat_id}/false_positive")
    async def mark_false_positive(threat_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute(
                "UPDATE threats SET false_positive=1, status='resolved' WHERE id=?",
                (threat_id,),
            )
            await db.commit()
        await audit(user.get("sub"), "false_positive", f"id={threat_id}", client_ip(request))
        return JSONResponse({"status": "ok"})

    @app.post("/api/threats/{threat_id}/quarantine")
    async def quarantine_threat(threat_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute(
                "SELECT id, endpoint_id, file_path FROM threats WHERE id=?",
                (threat_id,),
            ) as cur:
                threat = await cur.fetchone()
            if not threat or not threat["file_path"] or not threat["endpoint_id"]:
                raise HTTPException(status_code=404, detail="Threat has no file to quarantine")
            cur = await db.execute(
                """
                INSERT INTO agent_commands (endpoint_id, command, payload, status)
                VALUES (?, 'quarantine', ?, 'queued')
                """,
                (threat["endpoint_id"], json.dumps({
                    "threat_id": threat["id"],
                    "file_path": threat["file_path"],
                })),
            )
            await db.commit()
        await audit(user.get("sub"), "quarantine_request", f"threat={threat_id}", client_ip(request))
        return JSONResponse({"status": "queued", "command_id": cur.lastrowid})

    # ─── Quarantine ──────────────────────────────────────────────────────────

    @app.get("/quarantine", response_class=HTMLResponse)
    async def quarantine_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("""
                SELECT q.*, e.hostname, t.name as threat_name FROM quarantine q
                LEFT JOIN endpoints e ON q.endpoint_id=e.id
                LEFT JOIN threats t ON q.threat_id=t.id
                ORDER BY q.quarantined_at DESC
            """) as cur:
                items = [dict(r) for r in await cur.fetchall()]
        return render(request, "quarantine.html", {"request": request, "user": user, "items": items})

    @app.post("/api/quarantine/add")
    async def add_quarantine(request: Request):
        endpoint = await _require_agent(request, approved_only=True)
        data = await request.json()
        original = _clip(data.get("original_path"), 1024)
        quarantined = _clip(data.get("quarantine_path"), 1024)
        if not original or not quarantined:
            raise HTTPException(status_code=400, detail="original_path and quarantine_path are required")
        db = await get_db()
        async with db:
            cur = await db.execute(
                """
                INSERT INTO quarantine (endpoint_id, threat_id, original_path, quarantine_path, file_hash, file_size)
                VALUES (?,?,?,?,?,?)
                """,
                (
                    endpoint["id"],
                    data.get("threat_id") if isinstance(data.get("threat_id"), int) else None,
                    original, quarantined,
                    _clip(data.get("file_hash"), 128),
                    data.get("file_size") if isinstance(data.get("file_size"), int) else None,
                ),
            )
            await db.commit()
        return JSONResponse({"status": "quarantined", "id": cur.lastrowid})

    async def _queue_quarantine_action(item_id: int, action: str, user: dict, request: Request):
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("SELECT * FROM quarantine WHERE id=?", (item_id,)) as cur:
                item = await cur.fetchone()
            if not item:
                raise HTTPException(status_code=404, detail="Quarantine item not found")
            if item["restored"]:
                raise HTTPException(status_code=409, detail="File was already restored")
            if not item["quarantine_path"]:
                raise HTTPException(status_code=400, detail="Agent did not report a quarantine path")
            if item["pending_action"]:
                return JSONResponse({"status": "queued", "pending_action": item["pending_action"]})
            cur = await db.execute(
                """
                INSERT INTO agent_commands (endpoint_id, command, payload, status)
                VALUES (?,?,?,'queued')
                """,
                (item["endpoint_id"], action, json.dumps({
                    "quarantine_id": item["id"],
                    "original_path": item["original_path"],
                    "quarantine_path": item["quarantine_path"],
                })),
            )
            await db.execute(
                "UPDATE quarantine SET pending_action=? WHERE id=?",
                (action, item_id),
            )
            await db.commit()
            command_id = cur.lastrowid
        await audit(user.get("sub"), f"quarantine_{action}", f"id={item_id}", client_ip(request))
        return JSONResponse({"status": "queued", "command_id": command_id})

    @app.post("/api/quarantine/{item_id}/restore")
    async def restore_quarantine(item_id: int, request: Request, user=Depends(require_api_auth)):
        return await _queue_quarantine_action(item_id, "restore", user, request)

    @app.delete("/api/quarantine/{item_id}")
    async def delete_quarantine(item_id: int, request: Request, user=Depends(require_api_auth)):
        return await _queue_quarantine_action(item_id, "purge", user, request)

    # ─── Agent commands ──────────────────────────────────────────────────────

    @app.get("/api/agent/commands")
    async def agent_commands(request: Request):
        endpoint = await _require_agent(request, approved_only=True)
        return JSONResponse({"commands": await claim_commands(endpoint["id"])})

    @app.get("/api/scan/commands")
    async def get_commands(request: Request):
        endpoint = await _require_agent(request, approved_only=True)
        return JSONResponse({"commands": await claim_commands(endpoint["id"])})

    @app.post("/api/agent/commands/{command_id}/result")
    async def command_result(command_id: int, request: Request):
        endpoint = await _require_agent(request, approved_only=True)
        data = await request.json()
        status = data.get("status")
        if status not in ("done", "failed"):
            raise HTTPException(status_code=400, detail="status must be done or failed")
        detail = _clip(data.get("detail"), 500)
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute(
                "SELECT * FROM agent_commands WHERE id=? AND endpoint_id=?",
                (command_id, endpoint["id"]),
            ) as cur:
                command = await cur.fetchone()
            if not command:
                raise HTTPException(status_code=404, detail="Command not found")
            await db.execute(
                """
                UPDATE agent_commands
                SET status=?, result=?, completed_at=datetime('now')
                WHERE id=? AND endpoint_id=?
                """,
                (status, detail, command_id, endpoint["id"]),
            )
            try:
                payload = json.loads(command["payload"] or "{}")
            except json.JSONDecodeError:
                payload = {}
            quarantine_id = payload.get("quarantine_id")
            if quarantine_id:
                if status == "done" and command["command"] == "restore":
                    await db.execute(
                        """
                        UPDATE quarantine
                        SET restored=1, restored_at=datetime('now'), pending_action=NULL
                        WHERE id=? AND endpoint_id=?
                        """,
                        (quarantine_id, endpoint["id"]),
                    )
                elif status == "done" and command["command"] == "purge":
                    await db.execute(
                        "DELETE FROM quarantine WHERE id=? AND endpoint_id=?",
                        (quarantine_id, endpoint["id"]),
                    )
                elif status == "failed":
                    await db.execute(
                        "UPDATE quarantine SET pending_action=NULL WHERE id=? AND endpoint_id=?",
                        (quarantine_id, endpoint["id"]),
                    )
            await db.commit()
        return JSONResponse({"status": "ok"})

    # ─── YARA Rules ──────────────────────────────────────────────────────────

    @app.get("/yara", response_class=HTMLResponse)
    async def yara_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("SELECT * FROM yara_rules ORDER BY category, name") as cur:
                rules = [dict(r) for r in await cur.fetchall()]
        return render(request, "yara_rules.html", {"request": request, "user": user, "rules": rules})

    @app.post("/api/yara/add")
    async def add_yara_rule(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        name = _clip(data.get("name"), 120)
        content = data.get("rule_content") or ""
        if not name:
            raise HTTPException(status_code=400, detail="Rule name is required")
        _validate_yara(content)
        db = await get_db()
        async with db:
            await db.execute(
                """
                INSERT INTO yara_rules (name, category, description, rule_content, enabled)
                VALUES (?,?,?,?,1)
                """,
                (name, _clip(data.get("category"), 40) or "custom", _clip(data.get("description"), 500), content),
            )
            await db.commit()
        await audit(user.get("sub"), "yara_add", name, client_ip(request))
        return JSONResponse({"status": "added"})

    @app.put("/api/yara/{rule_id}")
    async def update_yara_rule(rule_id: int, request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        name = _clip(data.get("name"), 120)
        content = data.get("rule_content") or ""
        if not name:
            raise HTTPException(status_code=400, detail="Rule name is required")
        _validate_yara(content)
        enabled = 1 if data.get("enabled", 1) in (1, True, "1") else 0
        db = await get_db()
        async with db:
            await db.execute(
                """
                UPDATE yara_rules SET name=?, category=?, description=?, rule_content=?,
                enabled=?, updated_at=datetime('now') WHERE id=?
                """,
                (name, _clip(data.get("category"), 40) or "custom", _clip(data.get("description"), 500),
                 content, enabled, rule_id),
            )
            await db.commit()
        await audit(user.get("sub"), "yara_update", f"id={rule_id}", client_ip(request))
        return JSONResponse({"status": "updated"})

    @app.delete("/api/yara/{rule_id}")
    async def delete_yara_rule(rule_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            await db.execute("DELETE FROM yara_rules WHERE id=?", (rule_id,))
            await db.commit()
        await audit(user.get("sub"), "yara_delete", f"id={rule_id}", client_ip(request))
        return JSONResponse({"status": "deleted"})

    @app.get("/api/yara/export")
    async def export_yara_rules(request: Request):
        agent_token = request.headers.get("X-Agent-Token", "")
        if agent_token:
            if not await endpoint_from_token(agent_token, approved_only=True):
                raise HTTPException(status_code=403, detail="Unknown or unapproved agent")
        else:
            await require_api_auth(request)
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("SELECT rule_content FROM yara_rules WHERE enabled=1") as cur:
                rules = [r["rule_content"] for r in await cur.fetchall()]
        return Response(content="\n\n".join(rules), media_type="text/plain")

    # ─── IoC Feeds ───────────────────────────────────────────────────────────

    @app.get("/ioc", response_class=HTMLResponse)
    async def ioc_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
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
        return render(request, "ioc_feeds.html", {
            "request": request, "user": user, "feeds": feeds,
            "ip_count": ip_count, "domain_count": domain_count,
            "hash_count": hash_count, "recent": recent,
        })

    @app.post("/api/ioc/feeds/update")
    async def update_ioc_feeds(request: Request, user=Depends(require_api_auth)):
        from core.ioc_feeds import update_all_feeds
        asyncio.create_task(update_all_feeds())
        await audit(user.get("sub"), "ioc_update", None, client_ip(request))
        return JSONResponse({"status": "started"})

    @app.post("/api/ioc/check")
    async def check_ioc(request: Request):
        token = request.headers.get("X-Agent-Token", "")
        if token:
            if not await endpoint_from_token(token, approved_only=True):
                raise HTTPException(status_code=403, detail="Unknown or unapproved agent")
        else:
            await require_api_auth(request)
        data = await request.json()
        value = (data.get("value") or "").strip().lower()[:512]
        ioc_type = (data.get("type") or "")[:32]
        if not value or not ioc_type:
            raise HTTPException(status_code=400, detail="type and value are required")
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute(
                "SELECT ioc_type, value, threat_name, source, severity FROM ioc_entries WHERE ioc_type=? AND value=?",
                (ioc_type, value),
            ) as cur:
                match = await cur.fetchone()
        if match:
            return JSONResponse({"found": True, "threat": dict(match)})
        return JSONResponse({"found": False})

    @app.get("/api/ioc/export")
    async def export_iocs(request: Request):
        await _require_agent(request, approved_only=True)
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute(
                "SELECT ioc_type, value, threat_name, severity, source FROM ioc_entries"
            ) as cur:
                entries = [dict(r) for r in await cur.fetchall()]
        return JSONResponse({"count": len(entries), "entries": entries})

    # ─── Settings ────────────────────────────────────────────────────────────

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("SELECT * FROM settings") as cur:
                rows = await cur.fetchall()
                settings = {r["key"]: r["value"] for r in rows}
            async with db.execute(
                "SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at"
            ) as cur:
                users = [dict(r) for r in await cur.fetchall()]
        public = {key: value for key, value in settings.items() if key not in ("vt_api_key", "threatfox_auth_key")}
        return render(request, "settings.html", {
            "request": request, "user": user, "settings": public, "users": users,
            "vt_api_key_set": bool(settings.get("vt_api_key")),
            "threatfox_auth_key_set": bool(settings.get("threatfox_auth_key")),
        })

    @app.post("/api/settings")
    async def save_settings(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        db = await get_db()
        async with db:
            for key, value in data.items():
                if key not in ALLOWED_SETTINGS:
                    continue
                text = str(value)[:512]
                if key in _BOOL_SETTINGS and text not in ("0", "1"):
                    continue
                if key in _INT_SETTINGS:
                    if not text.isdigit():
                        continue
                    number = int(text)
                    if key == "ioc_update_interval_hours" and not 1 <= number <= 168:
                        continue
                    if key == "retention_days" and number < 7:
                        continue
                    if key == "agent_heartbeat_interval" and not 15 <= number <= 3600:
                        continue
                if key in ("vt_api_key", "threatfox_auth_key") and text == "":
                    continue
                await db.execute(
                    """
                    INSERT INTO settings (key, value, updated_at) VALUES (?,?,datetime('now'))
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                    """,
                    (key, text),
                )
            await db.commit()
        await audit(user.get("sub"), "settings", ",".join(sorted(data.keys())), client_ip(request))
        return JSONResponse({"status": "saved"})

    @app.post("/api/users/add")
    async def add_user(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        username = data.get("username") or ""
        password = data.get("password") or ""
        if not _USERNAME.match(username):
            raise HTTPException(status_code=400, detail="Invalid username")
        problem = validate_new_password(password)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        db = await get_db()
        async with db:
            await db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?, 'admin')",
                (username, hash_password(password)),
            )
            await db.commit()
        await audit(user.get("sub"), "add_user", username, client_ip(request))
        return JSONResponse({"status": "created"})

    @app.delete("/api/users/{user_id}")
    async def delete_user(user_id: int, request: Request, user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("SELECT COUNT(*) as c FROM users") as cur:
                if (await cur.fetchone())["c"] <= 1:
                    raise HTTPException(status_code=400, detail="Cannot delete the last administrator")
            async with db.execute("SELECT username FROM users WHERE id=?", (user_id,)) as cur:
                row = await cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            if row["username"] == user.get("sub"):
                raise HTTPException(status_code=400, detail="Cannot delete the signed-in administrator")
            await db.execute("DELETE FROM users WHERE id=?", (user_id,))
            await db.commit()
        await audit(user.get("sub"), "delete_user", row["username"], client_ip(request))
        return JSONResponse({"status": "deleted"})

    # ─── Scan Console ────────────────────────────────────────────────────────

    @app.get("/scan", response_class=HTMLResponse)
    async def scan_page(request: Request, user=Depends(require_auth)):
        if isinstance(user, RedirectResponse):
            return user
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute("""
                SELECT s.*, e.hostname FROM scan_jobs s
                LEFT JOIN endpoints e ON s.endpoint_id=e.id
                ORDER BY s.created_at DESC LIMIT 50
            """) as cur:
                jobs = [dict(r) for r in await cur.fetchall()]
            async with db.execute(
                "SELECT id, hostname, ip_address, status, approved FROM endpoints WHERE approved=1 ORDER BY hostname"
            ) as cur:
                endpoints = [dict(r) for r in await cur.fetchall()]
        return render(request, "scan.html", {
            "request": request, "user": user,
            "scan_jobs": jobs, "endpoints": endpoints,
        })

    @app.post("/api/scan/start")
    async def start_scan(request: Request, user=Depends(require_api_auth)):
        data = await request.json()
        endpoint_id = data.get("endpoint_id")
        scan_type = data.get("scan_type") or "quick"
        if scan_type not in ("quick", "full", "custom", "memory", "rootkit"):
            raise HTTPException(status_code=400, detail="Unknown scan type")
        target_path = _clip(data.get("target_path") or "/", 1024)
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            if endpoint_id:
                async with db.execute(
                    "SELECT id, hostname FROM endpoints WHERE id=? AND approved=1 AND status='online'",
                    (endpoint_id,),
                ) as cur:
                    endpoints = [dict(r) for r in await cur.fetchall()]
            else:
                async with db.execute(
                    "SELECT id, hostname FROM endpoints WHERE approved=1 AND status='online'"
                ) as cur:
                    endpoints = [dict(r) for r in await cur.fetchall()]
            if not endpoints:
                return JSONResponse({"status": "error", "message": "No online endpoints found"})
            job_ids = []
            for ep in endpoints:
                job = await db.execute(
                    """
                    INSERT INTO scan_jobs (endpoint_id, scan_type, target_path, status, created_at)
                    VALUES (?,?,?,'queued',datetime('now'))
                    """,
                    (ep["id"], scan_type, target_path),
                )
                job_id = job.lastrowid
                cmd = await db.execute(
                    """
                    INSERT INTO agent_commands (endpoint_id, command, payload, status)
                    VALUES (?, 'scan', ?, 'queued')
                    """,
                    (ep["id"], json.dumps({
                        "scan_type": scan_type,
                        "target_path": target_path,
                        "scan_job_id": job_id,
                    })),
                )
                await db.execute(
                    "UPDATE scan_jobs SET command_id=? WHERE id=?",
                    (cmd.lastrowid, job_id),
                )
                job_ids.append(job_id)
                add_scan_event({
                    "type": "scan_start",
                    "endpoint": ep["hostname"],
                    "endpoint_id": ep["id"],
                    "scan_type": scan_type,
                    "target_path": target_path,
                    "job_id": job_id,
                })
            await db.commit()
        await audit(user.get("sub"), "scan_start", f"type={scan_type} endpoints={len(endpoints)}", client_ip(request))
        return JSONResponse({
            "status": "ok",
            "job_id": job_ids[0] if len(job_ids) == 1 else job_ids,
            "endpoints": len(endpoints),
        })

    @app.get("/api/scan/jobs")
    async def get_scan_jobs(limit: int = 20, user=Depends(require_api_auth)):
        limit = min(max(limit, 1), 100)
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            async with db.execute(
                """
                SELECT s.*, e.hostname,
                    CASE WHEN s.completed_at IS NOT NULL AND s.started_at IS NOT NULL
                    THEN ROUND((julianday(s.completed_at)-julianday(s.started_at))*86400,1)||'s'
                    ELSE NULL END as duration
                FROM scan_jobs s
                LEFT JOIN endpoints e ON s.endpoint_id=e.id
                ORDER BY s.created_at DESC LIMIT ?
                """,
                (limit,),
            ) as cur:
                jobs = [dict(r) for r in await cur.fetchall()]
        return JSONResponse(jobs)

    @app.get("/api/scan/events")
    async def get_scan_events_api(limit: int = 100, user=Depends(require_api_auth)):
        return JSONResponse(get_scan_events(min(max(limit, 1), 500)))

    @app.post("/api/scan/report")
    async def report_scan(request: Request):
        endpoint = await _require_agent(request, approved_only=True)
        data = await request.json()
        event_type = _clip(data.get("type"), 40) or "scan_progress"
        safe = {
            "type": event_type,
            "endpoint": endpoint["hostname"],
            "endpoint_id": endpoint["id"],
            "scan_type": _clip(data.get("scan_type"), 40),
            "target_path": _clip(data.get("target_path"), 1024),
            "files_scanned": data.get("files_scanned") if isinstance(data.get("files_scanned"), int) else None,
            "threats_found": data.get("threats_found") if isinstance(data.get("threats_found"), int) else None,
            "severity": data.get("severity") if data.get("severity") in _SEVERITIES else None,
            "name": _clip(data.get("name"), 200),
            "file_path": _clip(data.get("file_path"), 1024),
            "job_id": data.get("scan_job_id") if isinstance(data.get("scan_job_id"), int) else None,
        }
        add_scan_event({k: v for k, v in safe.items() if v is not None})
        if event_type == "scan_complete" and isinstance(data.get("scan_job_id"), int):
            db = await get_db()
            async with db:
                await db.execute(
                    """
                    UPDATE scan_jobs
                    SET status='completed', started_at=COALESCE(started_at, ?),
                        completed_at=datetime('now'),
                        files_scanned=?, threats_found=?
                    WHERE id=? AND endpoint_id=?
                    """,
                    (
                        _clip(data.get("started_at"), 40),
                        data.get("files_scanned") if isinstance(data.get("files_scanned"), int) else 0,
                        data.get("threats_found") if isinstance(data.get("threats_found"), int) else 0,
                        data["scan_job_id"],
                        endpoint["id"],
                    ),
                )
                if isinstance(data.get("command_id"), int):
                    await db.execute(
                        """
                        UPDATE agent_commands
                        SET status='done', completed_at=datetime('now')
                        WHERE id=? AND endpoint_id=? AND command='scan'
                        """,
                        (data["command_id"], endpoint["id"]),
                    )
                await db.commit()
        return JSONResponse({"status": "ok"})

    # ─── WebSocket — cookie session only ─────────────────────────────────────

    @app.websocket("/ws/scan")
    async def ws_scan(websocket: WebSocket):
        cookie_token = websocket.cookies.get("aegisedr_token", "")
        if not cookie_token:
            await websocket.close(code=1008)
            return
        try:
            payload = decode_token(cookie_token)
            if payload.get("role") != "admin":
                await websocket.close(code=1008)
                return
        except Exception:
            await websocket.close(code=1008)
            return

        await websocket.accept()
        register_ws(websocket)
        for event in get_scan_events(20):
            try:
                await websocket.send_text(json.dumps(event))
            except Exception:
                break
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            unregister_ws(websocket)

    # ─── Agent file serving ──────────────────────────────────────────────────

    async def _serve_text(relative: str, newline: str | None = None):
        import aiofiles
        path = os.path.join(os.path.dirname(__file__), "..", relative)
        if not os.path.isfile(path):
            raise HTTPException(status_code=404, detail="File not found")
        async with aiofiles.open(path, "r") as handle:
            content = await handle.read()
        if newline == "crlf":
            content = content.replace("\r\n", "\n").replace("\n", "\r\n")
            return Response(content=b"\xef\xbb\xbf" + content.encode("utf-8"), media_type="text/plain; charset=utf-8")
        return HTMLResponse(content=content, media_type="text/plain")

    @app.get("/agent/agent_linux.py")
    async def serve_linux_agent():
        return await _serve_text(os.path.join("agent", "agent_linux.py"))

    @app.get("/agent/agent_windows.py")
    async def serve_windows_agent():
        return await _serve_text(os.path.join("agent", "agent_windows.py"))

    @app.get("/agent/edr_common.py")
    async def serve_agent_common():
        return await _serve_text(os.path.join("agent", "edr_common.py"))

    @app.get("/agent/app_windows.py")
    async def serve_windows_app():
        return await _serve_text(os.path.join("agent", "app_windows.py"))

    @app.get("/agent/tray_windows.py")
    async def serve_windows_tray():
        return await _serve_text(os.path.join("agent", "tray_windows.py"))

    @app.get("/agent/install.sh")
    async def serve_linux_install():
        return await _serve_text(os.path.join("agent", "install_linux.sh"))

    @app.get("/agent/install.ps1")
    async def serve_windows_install():
        return await _serve_text(os.path.join("agent", "install_windows.ps1"), newline="crlf")

    @app.get("/api/ca")
    async def serve_ca_cert():
        if not os.path.isfile(TLS_CERT_PATH):
            raise HTTPException(status_code=404, detail="Console certificate is not available")
        with open(TLS_CERT_PATH, "rb") as handle:
            content = handle.read()
        if b"BEGIN CERTIFICATE" not in content:
            raise HTTPException(status_code=404, detail="Console certificate is not available")
        return Response(content=content, media_type="application/x-pem-file")

    @app.get("/agent/AegisEDR-Agent-1.0.0-x64.msi")
    async def serve_windows_msi():
        from fastapi.responses import FileResponse
        root = os.path.dirname(__file__)
        candidates = [
            os.path.join(root, "..", "downloads", "AegisEDR-Agent-1.0.0-x64.msi"),
            os.path.join(root, "..", "dist", "AegisEDR-Agent-1.0.0-x64.msi"),
        ]
        path = next((p for p in candidates if os.path.isfile(p)), None)
        if not path:
            raise HTTPException(status_code=404, detail="MSI not yet built. Run agent/build_msi.ps1 on the server.")
        return FileResponse(
            path, media_type="application/octet-stream",
            filename="AegisEDR-Agent-1.0.0-x64.msi",
        )

    @app.get("/api/stats")
    async def get_stats(user=Depends(require_api_auth)):
        db = await get_db()
        async with db:
            db.row_factory = __import__("aiosqlite").Row
            stats = {}
            for table in ["endpoints", "threats", "quarantine", "ioc_entries", "yara_rules"]:
                async with db.execute(f"SELECT COUNT(*) as c FROM {table}") as cur:
                    stats[table] = (await cur.fetchone())["c"]
            async with db.execute(
                "SELECT severity, COUNT(*) as c FROM threats WHERE status='active' GROUP BY severity"
            ) as cur:
                stats["threats_by_severity"] = {r["severity"]: r["c"] for r in await cur.fetchall()}
        return JSONResponse(stats)
