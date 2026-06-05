import aiosqlite
import asyncio
import os
from config import DB_PATH

async def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return aiosqlite.connect(DB_PATH)

async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
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
                agent_token TEXT UNIQUE NOT NULL,
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
                restored_at TEXT
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
                created_at TEXT DEFAULT (datetime('now'))
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
        """)

        # Default settings
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
        await db.commit()
