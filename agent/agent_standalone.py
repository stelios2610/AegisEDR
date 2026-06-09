"""
AegisEDR Standalone Agent
Provides local-only protection - no central server required.
All data stored in C:\\ProgramData\\AegisEDR\\aegisedr.db
Build: pyinstaller --onefile --noconsole --name AegisEDR-Agent
       --add-data "yara_rules;yara_rules" agent_standalone.py
"""
import os
import sys
import time
import json
import socket
import hashlib
import logging
import threading
import subprocess
import sqlite3
import ctypes
import platform
import math
import tempfile
from datetime import datetime
from pathlib import Path

AGENT_VERSION  = "2.0.0"
DATA_DIR       = r"C:\ProgramData\AegisEDR"
DB_PATH        = os.path.join(DATA_DIR, "aegisedr.db")
LOG_PATH       = os.path.join(DATA_DIR, "agent.log")
QUARANTINE_DIR = os.path.join(DATA_DIR, "Quarantine")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("aegisedr")

# ── Database ──────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS threats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            file_path       TEXT,
            severity        TEXT    DEFAULT 'medium',
            threat_type     TEXT    DEFAULT 'malware',
            detected_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            status          TEXT    DEFAULT 'active',
            quarantine_path TEXT,
            file_hash       TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type       TEXT    NOT NULL,
            status          TEXT    DEFAULT 'pending',
            started_at      DATETIME,
            completed_at    DATETIME,
            files_scanned   INTEGER DEFAULT 0,
            threats_found   INTEGER DEFAULT 0,
            error_msg       TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_queue (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type       TEXT    NOT NULL,
            scan_path       TEXT,
            requested_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            status          TEXT    DEFAULT 'pending'
        );
        CREATE TABLE IF NOT EXISTS quarantine (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path   TEXT    NOT NULL,
            quarantine_path TEXT    NOT NULL,
            file_hash       TEXT,
            file_size       INTEGER,
            quarantined_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_id       INTEGER
        );
        CREATE TABLE IF NOT EXISTS ioc_hashes (
            hash            TEXT    PRIMARY KEY,
            threat_name     TEXT,
            severity        TEXT    DEFAULT 'critical',
            added_at        DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings (
            key             TEXT    PRIMARY KEY,
            value           TEXT
        );
        """)
        conn.execute("INSERT OR IGNORE INTO settings VALUES ('realtime_enabled', '1')")
        conn.execute("INSERT OR IGNORE INTO settings VALUES ('agent_version', ?)", (AGENT_VERSION,))
        conn.execute("INSERT OR IGNORE INTO settings VALUES ('hostname', ?)", (socket.gethostname(),))
        conn.execute("INSERT OR IGNORE INTO settings VALUES ('os_version', ?)", (platform.version()[:80],))
        conn.execute("INSERT OR IGNORE INTO settings VALUES ('protection_status', 'starting')")
        conn.execute("INSERT OR IGNORE INTO settings VALUES ('last_seen', ?)", (datetime.now().isoformat(),))
        conn.commit()
    log.info("Database initialized")

def get_setting(key: str, default=None) -> str:
    try:
        with get_db() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default
    except Exception:
        return default

def set_setting(key: str, value: str):
    try:
        with get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", (key, str(value)))
            conn.commit()
    except Exception:
        pass

# ── Utilities ──────────────────────────────────────────────────────────────────
def sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def file_entropy(path: str) -> float:
    try:
        data = open(path, "rb").read(65536)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        for f in freq:
            if f:
                p = f / len(data)
                entropy -= p * math.log2(p)
        return entropy
    except Exception:
        return 0.0

# ── YARA ───────────────────────────────────────────────────────────────────────
_yara_rules        = None
_yara_exe_path     = None
_yara_rules_file   = None
_yara_lock         = threading.Lock()

def _find_rules_dir() -> str | None:
    candidates = [
        os.path.join(getattr(sys, "_MEIPASS", ""), "yara_rules"),
        os.path.join(DATA_DIR, "rules"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "yara_rules"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules"),
        r"C:\Program Files\AegisEDR\yara_rules",
    ]
    for p in candidates:
        if os.path.isdir(p):
            return p
    return None

def _find_yara_exe() -> str | None:
    candidates = [
        os.path.join(getattr(sys, "_MEIPASS", ""), "yara64.exe"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_bin", "yara64.exe"),
        r"C:\Program Files\AegisEDR\yara64.exe",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None

def load_yara_rules():
    global _yara_rules, _yara_exe_path, _yara_rules_file
    rules_dir = _find_rules_dir()

    # Merge all .yar files into one temp file (for subprocess yara64 fallback)
    merged = ""
    if rules_dir:
        for fname in os.listdir(rules_dir):
            if fname.endswith(".yar"):
                try:
                    merged += open(os.path.join(rules_dir, fname), encoding="utf-8").read() + "\n"
                except Exception:
                    pass

    # Write merged rules to DATA_DIR for persistence
    if merged:
        merged_path = os.path.join(DATA_DIR, "rules_merged.yar")
        with open(merged_path, "w", encoding="utf-8") as f:
            f.write(merged)
        _yara_rules_file = merged_path

    # Try yara-python library first (preferred)
    try:
        import yara
        if rules_dir:
            fp = {f"ns_{i}": os.path.join(rules_dir, fname)
                  for i, fname in enumerate(
                      f for f in os.listdir(rules_dir) if f.endswith(".yar")
                  )}
            if fp:
                with _yara_lock:
                    _yara_rules = yara.compile(filepaths=fp)
                log.info(f"YARA (yara-python): {len(fp)} rule files loaded")
                return
    except ImportError:
        pass
    except Exception as e:
        log.warning(f"yara-python compile failed: {e}")

    # Fallback: yara64.exe subprocess
    exe = _find_yara_exe()
    if exe:
        _yara_exe_path = exe
        log.info(f"YARA (subprocess): {exe}")
    elif not merged:
        log.warning("No YARA rules found — signature scanning disabled")

def scan_with_yara(file_path: str) -> list[str]:
    with _yara_lock:
        rules = _yara_rules
        exe   = _yara_exe_path
        rf    = _yara_rules_file

    # yara-python
    if rules:
        try:
            matches = rules.match(file_path, timeout=15)
            return [m.rule for m in matches]
        except Exception:
            return []

    # subprocess yara64.exe
    if exe and rf and os.path.isfile(rf):
        try:
            res = subprocess.run([exe, rf, file_path],
                                  capture_output=True, text=True, timeout=15,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            return [line.split()[0] for line in res.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    return []

# ── IoC hash check ────────────────────────────────────────────────────────────
def check_ioc(file_hash: str) -> dict | None:
    if not file_hash:
        return None
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT threat_name, severity FROM ioc_hashes WHERE hash=?",
                (file_hash,)
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None

# ── Threat detection ──────────────────────────────────────────────────────────
_SCAN_EXTS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".jar",
              ".com", ".scr", ".pif", ".msi", ".hta", ".wsf", ".lnk"}

def scan_file(file_path: str) -> list[dict]:
    threats = []

    if QUARANTINE_DIR.lower() in file_path.lower():
        return []
    if DATA_DIR.lower() in file_path.lower():
        return []

    try:
        size = os.path.getsize(file_path)
        if size == 0 or size > 256 * 1024 * 1024:
            return []
    except Exception:
        return []

    file_hash = sha256_file(file_path)

    # IoC hash check
    ioc = check_ioc(file_hash)
    if ioc:
        threats.append({
            "name":        ioc["threat_name"],
            "file_path":   file_path,
            "severity":    ioc.get("severity", "critical"),
            "threat_type": "ioc_match",
            "file_hash":   file_hash
        })
        return threats

    ext = os.path.splitext(file_path)[1].lower()

    # YARA scan
    if ext in _SCAN_EXTS:
        matches = scan_with_yara(file_path)
        for rule_name in matches:
            rl = rule_name.lower()
            if any(k in rl for k in ["ransomware", "wannacry", "lockbit", "revil", "conti", "blackcat"]):
                sev = "critical"
            elif any(k in rl for k in ["keylogger", "trojan", "backdoor", "spyware", "rootkit"]):
                sev = "high"
            else:
                sev = "medium"
            threats.append({
                "name":        f"YARA:{rule_name}",
                "file_path":   file_path,
                "severity":    sev,
                "threat_type": "yara_match",
                "file_hash":   file_hash
            })

    # Entropy (packed/encrypted executables — possible ransomware dropper)
    if ext in {".exe", ".dll", ".com", ".scr"} and not threats:
        entropy = file_entropy(file_path)
        if entropy > 7.5:
            threats.append({
                "name":        "Suspicious:HighEntropy",
                "file_path":   file_path,
                "severity":    "medium",
                "threat_type": "heuristic",
                "file_hash":   file_hash
            })

    return threats

def save_threat(threat: dict) -> int:
    try:
        with get_db() as conn:
            if threat.get("file_hash"):
                existing = conn.execute(
                    "SELECT id FROM threats WHERE file_hash=? AND name=? AND status='active'",
                    (threat["file_hash"], threat["name"])
                ).fetchone()
                if existing:
                    return existing["id"]
            cur = conn.execute(
                "INSERT INTO threats (name, file_path, severity, threat_type, file_hash, status) "
                "VALUES (?,?,?,?,?,?)",
                (threat.get("name", "Unknown"), threat.get("file_path", ""),
                 threat.get("severity", "medium"), threat.get("threat_type", "malware"),
                 threat.get("file_hash", ""), "active")
            )
            conn.commit()
            log.warning(f"THREAT [{threat['severity'].upper()}]: {threat['name']} @ {threat.get('file_path','')}")
            return cur.lastrowid
    except Exception as e:
        log.error(f"save_threat: {e}")
        return -1

def quarantine_file(file_path: str, threat_id: int = None):
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        q_name = f"{int(time.time())}_{os.path.basename(file_path)}.quar"
        q_path = os.path.join(QUARANTINE_DIR, q_name)
        os.rename(file_path, q_path)
        file_hash = sha256_file(q_path)
        with get_db() as conn:
            conn.execute(
                "INSERT INTO quarantine (original_path, quarantine_path, file_hash, file_size, threat_id) "
                "VALUES (?,?,?,?,?)",
                (file_path, q_path, file_hash, os.path.getsize(q_path), threat_id)
            )
            if threat_id:
                conn.execute(
                    "UPDATE threats SET status='quarantined', quarantine_path=? WHERE id=?",
                    (q_path, threat_id)
                )
            conn.commit()
        log.info(f"Quarantined: {file_path}")
    except Exception as e:
        log.error(f"Quarantine failed: {e}")

# ── Real-time file watcher ────────────────────────────────────────────────────
_WATCH_DIRS = [
    os.path.expanduser("~\\Desktop"),
    os.path.expanduser("~\\Downloads"),
    os.path.expanduser("~\\Documents"),
    os.environ.get("TEMP", ""),
    r"C:\Windows\Temp",
    r"C:\Users\Public",
    r"C:\Temp",
]

_WATCH_EXTS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".jar",
               ".com", ".scr", ".pif", ".msi", ".hta", ".wsf", ".zip", ".rar", ".7z"}

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    class ThreatHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                self._check(event.src_path)

        def on_modified(self, event):
            if event.is_directory:
                return
            ext = os.path.splitext(event.src_path)[1].lower()
            if ext in {".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"}:
                self._check(event.src_path)

        def _check(self, path: str):
            if get_setting("realtime_enabled", "1") != "1":
                return
            ext = os.path.splitext(path)[1].lower()
            if ext not in _WATCH_EXTS:
                return
            time.sleep(0.4)  # let file finish writing
            threats = scan_file(path)
            quarantined = False
            for t in threats:
                tid = save_threat(t)
                if not quarantined and t.get("severity") in ("critical", "high") and tid > 0:
                    try:
                        quarantine_file(path, tid)
                        quarantined = True  # file moved — skip subsequent matches
                    except Exception:
                        pass

    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False

def start_realtime_protection():
    if not WATCHDOG_OK:
        log.warning("watchdog not installed — real-time protection disabled")
        set_setting("protection_status", "limited")
        return None

    observer = Observer()
    handler  = ThreatHandler()
    watched  = 0
    for d in _WATCH_DIRS:
        if d and os.path.isdir(d):
            try:
                observer.schedule(handler, d, recursive=True)
                watched += 1
            except Exception as e:
                log.warning(f"Cannot watch {d}: {e}")

    if watched > 0:
        observer.start()
        log.info(f"Real-time protection: watching {watched} directories")
        set_setting("protection_status", "active")
    else:
        log.warning("No watch directories available")
        set_setting("protection_status", "error")

    return observer

# ── Manual scan ───────────────────────────────────────────────────────────────
QUICK_DIRS = [
    os.path.expanduser("~\\Desktop"),
    os.path.expanduser("~\\Downloads"),
    os.path.expanduser("~\\Documents"),
    os.environ.get("TEMP", ""),
    r"C:\Windows\Temp",
    r"C:\Temp",
]

FULL_DIRS = [
    os.path.expanduser("~"),
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\ProgramData",
]

def run_scan(scan_type: str = "quick", scan_path: str = "", job_id: int = None):
    if scan_path and os.path.isdir(scan_path):
        scan_dirs = [scan_path]
    elif scan_type == "full":
        scan_dirs = FULL_DIRS
    else:
        scan_dirs = QUICK_DIRS

    if job_id is None:
        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO scan_jobs (scan_type, status, started_at) VALUES (?, 'running', CURRENT_TIMESTAMP)",
                (scan_type,)
            )
            conn.commit()
            job_id = cur.lastrowid
    else:
        with get_db() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status='running', started_at=CURRENT_TIMESTAMP WHERE id=?",
                (job_id,)
            )
            conn.commit()

    files_scanned = 0
    threats_found = 0

    log.info(f"Scan started: type={scan_type}, job={job_id}")

    try:
        for scan_dir in scan_dirs:
            if not scan_dir or not os.path.isdir(scan_dir):
                continue
            for root, dirs, files in os.walk(scan_dir, topdown=True):
                # Skip quarantine and data dirs
                dirs[:] = [d for d in dirs if
                           os.path.join(root, d).lower() not in
                           {QUARANTINE_DIR.lower(), DATA_DIR.lower()}]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in _SCAN_EXTS:
                        continue
                    fpath = os.path.join(root, fname)
                    found = scan_file(fpath)
                    files_scanned += 1
                    for t in found:
                        tid = save_threat(t)
                        threats_found += 1
                        if t.get("severity") in ("critical", "high") and tid > 0:
                            try:
                                quarantine_file(fpath, tid)
                            except Exception:
                                pass

                    if files_scanned % 100 == 0:
                        with get_db() as conn:
                            conn.execute(
                                "UPDATE scan_jobs SET files_scanned=?, threats_found=? WHERE id=?",
                                (files_scanned, threats_found, job_id)
                            )
                            conn.commit()

        with get_db() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status='completed', completed_at=CURRENT_TIMESTAMP, "
                "files_scanned=?, threats_found=? WHERE id=?",
                (files_scanned, threats_found, job_id)
            )
            conn.commit()
        set_setting("last_scan", datetime.now().isoformat())
        log.info(f"Scan complete: {files_scanned} files, {threats_found} threats (job {job_id})")

    except Exception as e:
        log.error(f"Scan error: {e}")
        with get_db() as conn:
            conn.execute(
                "UPDATE scan_jobs SET status='failed', error_msg=?, completed_at=CURRENT_TIMESTAMP WHERE id=?",
                (str(e), job_id)
            )
            conn.commit()

# ── Scan queue ────────────────────────────────────────────────────────────────
def poll_scan_queue():
    while True:
        try:
            with get_db() as conn:
                row = conn.execute(
                    "SELECT id, scan_type, scan_path FROM scan_queue "
                    "WHERE status='pending' ORDER BY id LIMIT 1"
                ).fetchone()
                if row:
                    conn.execute("UPDATE scan_queue SET status='running' WHERE id=?", (row["id"],))
                    conn.commit()
                    qid   = row["id"]
                    stype = row["scan_type"]
                    spath = row["scan_path"] or ""
                    threading.Thread(
                        target=_exec_queued_scan,
                        args=(qid, stype, spath),
                        daemon=True
                    ).start()
        except Exception as e:
            log.error(f"Scan queue: {e}")
        time.sleep(5)

def _exec_queued_scan(qid: int, scan_type: str, scan_path: str):
    try:
        run_scan(scan_type, scan_path)
    finally:
        try:
            with get_db() as conn:
                conn.execute("UPDATE scan_queue SET status='done' WHERE id=?", (qid,))
                conn.commit()
        except Exception:
            pass

# ── Heartbeat ─────────────────────────────────────────────────────────────────
def heartbeat():
    while True:
        try:
            set_setting("last_seen", datetime.now().isoformat())
        except Exception:
            pass
        time.sleep(30)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info(f"AegisEDR Standalone Agent v{AGENT_VERSION} starting...")

    init_db()
    load_yara_rules()

    observer = start_realtime_protection()
    threading.Thread(target=poll_scan_queue, daemon=True).start()
    threading.Thread(target=heartbeat, daemon=True).start()

    log.info("Protection active. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        if observer:
            observer.stop()
            observer.join()
        set_setting("protection_status", "stopped")

if __name__ == "__main__":
    main()
