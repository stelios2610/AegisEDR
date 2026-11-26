import logging
import os
import secrets

import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from config import (
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
    SETUP_TOKEN_FILE, MIN_PASSWORD_LENGTH,
)
from core.database import get_db, hash_agent_token

log = logging.getLogger("aegisedr.auth")


def hash_password(password: str) -> str:
    raw = password.encode()
    if len(raw) > 72:
        raise ValueError("Password must be at most 72 bytes")
    return bcrypt.hashpw(raw, bcrypt.gensalt(12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def validate_new_password(password: str) -> str | None:
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password.encode()) > 72:
        return "Password must be at most 72 bytes"
    return None


def create_token(username: str, role: str = "admin") -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": username, "role": role, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def create_agent_token() -> str:
    return secrets.token_urlsafe(32)


def cookie_secure(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto.split(",")[0].strip().lower() == "https"


async def get_current_user(request: Request):
    token = request.cookies.get("aegisedr_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_token(token)


async def require_auth(request: Request):
    token = request.cookies.get("aegisedr_token")
    if not token:
        return RedirectResponse("/login", status_code=302)
    try:
        return decode_token(token)
    except HTTPException:
        return RedirectResponse("/login", status_code=302)


async def require_api_auth(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = decode_token(auth[7:])
    else:
        token = request.cookies.get("aegisedr_token")
        if not token:
            raise HTTPException(status_code=401, detail="Unauthorized")
        payload = decode_token(token)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return payload


async def authenticate_user(username: str, password: str) -> dict | None:
    db = await get_db()
    async with db:
        db.row_factory = __import__("aiosqlite").Row
        async with db.execute("SELECT * FROM users WHERE username=?", (username,)) as cur:
            row = await cur.fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return None
        await db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (row["id"],))
        await db.commit()
        return dict(row)


async def user_count() -> int:
    db = await get_db()
    async with db:
        async with db.execute("SELECT COUNT(*) FROM users") as cur:
            row = await cur.fetchone()
            return int(row[0])


def _write_secret_file(path: str, value: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, value.encode())
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


async def ensure_setup_state():
    """Create a one-time setup token when the console has no users.

    There is no built-in admin account. The token is written to disk mode 0600
    and must be presented to /setup. It is deleted once an admin exists.
    """
    if await user_count() > 0:
        if os.path.exists(SETUP_TOKEN_FILE):
            try:
                os.remove(SETUP_TOKEN_FILE)
            except OSError:
                log.warning("Could not remove leftover setup token at %s", SETUP_TOKEN_FILE)
        return
    if os.path.exists(SETUP_TOKEN_FILE):
        try:
            if os.path.getsize(SETUP_TOKEN_FILE) >= 20:
                return
        except OSError:
            pass
    token = secrets.token_urlsafe(24)
    _write_secret_file(SETUP_TOKEN_FILE, token)
    log.warning("No console admin exists. One-time setup token written to %s", SETUP_TOKEN_FILE)


def read_setup_token() -> str:
    try:
        with open(SETUP_TOKEN_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def consume_setup_token():
    try:
        os.remove(SETUP_TOKEN_FILE)
    except OSError:
        pass


async def endpoint_from_token(token: str, approved_only: bool = False):
    if not token:
        return None
    digest = hash_agent_token(token)
    db = await get_db()
    async with db:
        db.row_factory = __import__("aiosqlite").Row
        sql = "SELECT * FROM endpoints WHERE agent_token_hash=?"
        if approved_only:
            sql += " AND approved=1"
        async with db.execute(sql, (digest,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None
