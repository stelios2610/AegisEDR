import bcrypt
import jwt
from datetime import datetime, timedelta
from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from core.database import get_db

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(username: str, role: str = "admin") -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "role": role, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def create_agent_token() -> str:
    import secrets
    return secrets.token_urlsafe(32)

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
        token = auth[7:]
        return decode_token(token)
    token = request.cookies.get("aegisedr_token")
    if token:
        return decode_token(token)
    raise HTTPException(status_code=401, detail="Unauthorized")

async def authenticate_user(username: str, password: str) -> dict | None:
    db = await get_db()
    try:
        async with db:
            db.row_factory = __import__('aiosqlite').Row
            async with db.execute("SELECT * FROM users WHERE username=?", (username,)) as cur:
                row = await cur.fetchone()
                if row and verify_password(password, row["password_hash"]):
                    await db.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (row["id"],))
                    await db.commit()
                    return dict(row)
    except Exception:
        pass
    return None

async def ensure_default_admin():
    db = await get_db()
    async with db:
        db.row_factory = __import__('aiosqlite').Row
        async with db.execute("SELECT COUNT(*) as cnt FROM users") as cur:
            row = await cur.fetchone()
            if row["cnt"] == 0:
                await db.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                    ("admin", hash_password("AegisEDR2024!"), "admin")
                )
                await db.commit()
