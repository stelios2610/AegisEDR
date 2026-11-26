import aiosqlite
import hashlib
import os
from config import DB_PATH


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return aiosqlite.connect(DB_PATH, timeout=5.0)


async def _columns(db, table: str) -> set[str]:
    async with db.execute(f"PRAGMA table_info({table})") as cur:
        return {row[1] for row in await cur.fetchall()}


async def _migrate(db):
    tables = set()
    async with db.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
        tables = {row[0] for row in await cur.fetchall()}

    if "endpoints" in tables:
        cols = await _columns(db, "endpoints")
        if "agent_token" in cols and "agent_token_hash" not in cols:
            await db.execute("ALTER TABLE endpoints ADD COLUMN agent_token_hash TEXT")
            async with db.execute("SELECT id, agent_token FROM endpoints") as cur:
                rows = await cur.fetchall()
            for endpoint_id, token in rows:
                if not token:
                    continue
                digest = hash_agent_token(token)
                await db.execute(
                    "UPDATE endpoints SET agent_token_hash=? WHERE id=?",
                    (digest, endpoint_id),
                )
            # The plaintext token must not remain in the database. Agents already
            # store their own copy and authenticate with it.
            await db.execute("UPDATE endpoints SET agent_token=''")
        if "agent_token_hash" in cols or "agent_token" in cols:
            await db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_token_hash ON endpoints(agent_token_hash)"
            )

    if "quarantine" in tables:
        cols = await _columns(db, "quarantine")
        if "pending_action" not in cols:
            await db.execute("ALTER TABLE quarantine ADD COLUMN pending_action TEXT")

    if "scan_jobs" in tables:
        cols = await _columns(db, "scan_jobs")
        if "command_id" not in cols:
            await db.execute("ALTER TABLE scan_jobs ADD COLUMN command_id INTEGER")


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH, timeout=5.0) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'admin',
                created_at TEXT DEFAULT (datetime('now')),
                last_login TEXT
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                os_type TEXT,
                os_version TEXT,
                agent_version TEXT,
                agent_token_hash TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'offline',
                approved INTEGER DEFAULT 0,
                last_seen TEXT,
                registered_at TEXT DEFAULT (datetime('now')),
                protection_enabled INTEGER DEFAULT 1,
                tags TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER REFERENCES endpoints(id),
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                file_hash TEXT,
                process_name TEXT,
                process_pid INTEGER,
                network_ip TEXT,
                network_domain TEXT,
                action_taken TEXT DEFAULT 'detected',
                status TEXT DEFAULT 'active',
                detected_at TEXT DEFAULT (datetime('now')),
                resolved_at TEXT,
                false_positive INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER REFERENCES endpoints(id),
                threat_id INTEGER REFERENCES threats(id),
                original_path TEXT NOT NULL,
                quarantine_path TEXT,
                file_hash TEXT,
                file_size INTEGER,
                quarantined_at TEXT DEFAULT (datetime('now')),
                restored INTEGER DEFAULT 0,
                restored_at TEXT,
                pending_action TEXT
            );

            CREATE TABLE IF NOT EXISTS yara_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT DEFAULT 'custom',
                description TEXT,
                rule_content TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                hit_count INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS ioc_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                threat_name TEXT,
                source TEXT,
                severity TEXT DEFAULT 'medium',
                added_at TEXT DEFAULT (datetime('now')),
                UNIQUE(ioc_type, value)
            );

            CREATE TABLE IF NOT EXISTS ioc_feed_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                feed_type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                last_updated TEXT,
                entry_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER REFERENCES endpoints(id),
                scan_type TEXT NOT NULL,
                target_path TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                files_scanned INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                command_id INTEGER
            );

            CREATE TABLE IF NOT EXISTS agent_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}',
                status TEXT DEFAULT 'queued',
                result TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                started_at TEXT,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS enrollment_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT UNIQUE NOT NULL,
                label TEXT,
                created_by TEXT,
                max_uses INTEGER NOT NULL DEFAULT 1,
                uses_remaining INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT,
                revoked INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket TEXT NOT NULL,
                ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_rate_limits_bucket ON rate_limits(bucket, ts);
            CREATE INDEX IF NOT EXISTS idx_agent_commands_ep ON agent_commands(endpoint_id, status);
            CREATE INDEX IF NOT EXISTS idx_threats_endpoint ON threats(endpoint_id, status);
        """)

        await db.execute("""
            INSERT OR IGNORE INTO settings (key, value) VALUES
            ('auto_quarantine', '1'),
            ('auto_block_ransomware', '1'),
            ('virustotal_enabled', '0'),
            ('ioc_auto_update', '1'),
            ('ioc_update_interval_hours', '6'),
            ('agent_heartbeat_interval', '60'),
            ('retention_days', '90')
        """)
        await _migrate(db)
        await db.commit()
