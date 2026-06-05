#!/usr/bin/env python3
"""
AegisEDR Linux Agent
Monitors the endpoint and reports threats to the console.
"""
import os
import sys
import time
import json
import socket
import hashlib
import platform
import subprocess
import threading
import logging
import signal
from pathlib import Path

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Configuration ────────────────────────────────────────────────────────────
CONFIG_PATH = "/etc/aegisedr-agent/config.json"
AGENT_VERSION = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/aegisedr-agent.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("aegisedr")

# ── Config management ─────────────────────────────────────────────────────────
def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}

def save_config(cfg: dict):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

# ── Registration ──────────────────────────────────────────────────────────────
def register(console_url: str) -> dict:
    data = {
        "hostname": socket.gethostname(),
        "ip_address": get_local_ip(),
        "os_type": "Linux",
        "os_version": platform.version()[:80],
        "agent_version": AGENT_VERSION
    }
    resp = requests.post(f"{console_url}/api/endpoints/register", json=data, verify=False, timeout=10)
    resp.raise_for_status()
    return resp.json()

def wait_for_adoption(console_url: str, endpoint_id: int, token: str):
    log.info("Waiting for admin adoption on console...")
    while True:
        try:
            resp = requests.get(
                f"{console_url}/api/endpoints/{endpoint_id}/status",
                headers={"X-Agent-Token": token},
                verify=False, timeout=10
            )
            data = resp.json()
            if data.get("approved"):
                log.info("Endpoint adopted! Starting protection...")
                return
            log.info("Still pending adoption... (check console to approve)")
        except Exception as e:
            log.warning(f"Console unreachable: {e}")
        time.sleep(30)

# ── Utilities ─────────────────────────────────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

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
    """Calculate Shannon entropy — high entropy = likely encrypted (ransomware)."""
    try:
        import math
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

# ── Threat reporting ──────────────────────────────────────────────────────────
def report_threat(console_url: str, token: str, threat: dict):
    try:
        requests.post(
            f"{console_url}/api/threats/report",
            json=threat,
            headers={"X-Agent-Token": token},
            verify=False, timeout=10
        )
        log.warning(f"THREAT REPORTED: [{threat['severity'].upper()}] {threat['name']}")
    except Exception as e:
        log.error(f"Failed to report threat: {e}")

def quarantine_file(console_url: str, token: str, file_path: str, threat_id: int = None):
    """Move file to quarantine dir and notify console."""
    try:
        q_dir = "/var/lib/aegisedr-agent/quarantine"
        os.makedirs(q_dir, exist_ok=True)
        q_name = f"{int(time.time())}_{os.path.basename(file_path)}.quar"
        q_path = os.path.join(q_dir, q_name)
        os.rename(file_path, q_path)
        os.chmod(q_path, 0o000)
        file_hash = sha256_file(q_path)
        requests.post(
            f"{console_url}/api/quarantine/add",
            json={
                "original_path": file_path,
                "quarantine_path": q_path,
                "file_hash": file_hash,
                "file_size": os.path.getsize(q_path),
                "threat_id": threat_id
            },
            headers={"X-Agent-Token": token},
            verify=False, timeout=10
        )
        log.info(f"Quarantined: {file_path} → {q_path}")
    except Exception as e:
        log.error(f"Quarantine failed for {file_path}: {e}")

# ── ClamAV Scanner ────────────────────────────────────────────────────────────
def scan_with_clamav(file_path: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["clamscan", "--no-summary", file_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 1:
            for line in result.stdout.splitlines():
                if "FOUND" in line:
                    name = line.split(":")[1].strip().replace(" FOUND", "")
                    return True, name
        return False, ""
    except FileNotFoundError:
        return False, ""  # ClamAV not installed
    except Exception:
        return False, ""

# ── YARA Scanner ──────────────────────────────────────────────────────────────
_yara_rules = None
_yara_lock = threading.Lock()

def load_yara_rules(console_url: str):
    global _yara_rules
    try:
        import yara
        resp = requests.get(f"{console_url}/api/yara/export", verify=False, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            rules = yara.compile(source=resp.text)
            with _yara_lock:
                _yara_rules = rules
            log.info("YARA rules loaded from console")
    except Exception as e:
        log.warning(f"YARA rules load failed: {e}")

def scan_with_yara(file_path: str) -> list[str]:
    with _yara_lock:
        rules = _yara_rules
    if not rules:
        return []
    try:
        matches = rules.match(file_path, timeout=10)
        return [m.rule for m in matches]
    except Exception:
        return []

# ── IoC Check ─────────────────────────────────────────────────────────────────
_ioc_cache: dict[str, dict] = {}

def check_ioc(console_url: str, token: str, value: str, ioc_type: str) -> dict | None:
    cache_key = f"{ioc_type}:{value}"
    if cache_key in _ioc_cache:
        return _ioc_cache[cache_key]
    try:
        resp = requests.post(
            f"{console_url}/api/ioc/check",
            json={"value": value, "type": ioc_type},
            headers={"X-Agent-Token": token},
            verify=False, timeout=5
        )
        data = resp.json()
        if data.get("found"):
            _ioc_cache[cache_key] = data["threat"]
            return data["threat"]
    except Exception:
        pass
    return None

# ── Anti-Ransomware ───────────────────────────────────────────────────────────
RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypted", ".locky", ".zepto",
    ".cerber", ".aaa", ".abc", ".xyz", ".zzz", ".micro", ".vvv",
    ".wncry", ".wcry", ".wncryt", ".lockbit", ".lb3", ".alphv",
    ".ryuk", ".revil", ".conti", ".blackcat"
}
RANSOM_NOTE_NAMES = {
    "readme.txt", "decrypt_instructions.txt", "how_to_decrypt.txt",
    "restore-my-files.txt", "your_files_are_encrypted.txt",
    "recover_files.txt", "ransom_note.txt", "@please_read_me@.txt"
}

_rename_counter: dict[str, int] = {}
_rename_lock = threading.Lock()

def check_ransomware_behavior(file_path: str) -> str | None:
    """Returns threat description if ransomware behavior detected."""
    fname = os.path.basename(file_path).lower()
    ext = Path(file_path).suffix.lower()

    if ext in RANSOM_EXTENSIONS:
        return f"File renamed with ransomware extension: {ext}"

    if fname in RANSOM_NOTE_NAMES:
        return f"Ransom note created: {fname}"

    # High entropy check for newly written files
    if os.path.exists(file_path) and os.path.getsize(file_path) > 1024:
        entropy = file_entropy(file_path)
        if entropy > 7.8:
            with _rename_lock:
                parent = os.path.dirname(file_path)
                _rename_counter[parent] = _rename_counter.get(parent, 0) + 1
                if _rename_counter[parent] > 20:
                    return f"Mass file encryption detected (entropy={entropy:.2f})"

    return None

def setup_canary_files():
    """Create canary files in key directories. If modified → ransomware."""
    canary_dirs = [
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Desktop"),
        "/tmp"
    ]
    canary_paths = []
    for d in canary_dirs:
        if os.path.isdir(d):
            path = os.path.join(d, ".aegisedr_canary_do_not_touch")
            try:
                with open(path, "w") as f:
                    f.write("AegisEDR canary file — do not modify")
                canary_paths.append(path)
            except Exception:
                pass
    return canary_paths

# ── File System Monitor ───────────────────────────────────────────────────────
SKIP_EXTENSIONS = {".log", ".tmp", ".swp", ".pyc", ".sock", ".pid"}
SCAN_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".sh",
    ".py", ".elf", ".bin", ".msi", ".jar", ".apk", ".deb", ".rpm"
}
MAX_SCAN_SIZE = 50 * 1024 * 1024  # 50MB

class FileMonitor(FileSystemEventHandler):
    def __init__(self, console_url: str, token: str, canaries: list[str]):
        self.console_url = console_url
        self.token = token
        self.canaries = set(canaries)
        self._scan_lock = threading.Semaphore(4)

    def on_created(self, event):
        if not event.is_directory:
            threading.Thread(target=self._handle, args=(event.src_path, "created"), daemon=True).start()

    def on_modified(self, event):
        if not event.is_directory:
            threading.Thread(target=self._handle, args=(event.src_path, "modified"), daemon=True).start()

    def _handle(self, path: str, event_type: str):
        if not os.path.isfile(path):
            return

        # Canary file tampered
        if path in self.canaries:
            self._report({
                "threat_type": "ransomware",
                "severity": "critical",
                "name": "Ransomware Canary Triggered",
                "description": f"Canary file modified: {path} — immediate ransomware response",
                "file_path": path,
                "action_taken": "alert"
            })
            return

        ext = Path(path).suffix.lower()
        if ext in SKIP_EXTENSIONS:
            return

        # Anti-ransomware check (any file)
        ransom_desc = check_ransomware_behavior(path)
        if ransom_desc:
            self._report({
                "threat_type": "ransomware",
                "severity": "critical",
                "name": "Ransomware Activity Detected",
                "description": ransom_desc,
                "file_path": path,
                "action_taken": "alert"
            })
            return

        # Deep scan only for executable-type files
        if ext not in SCAN_EXTENSIONS:
            return
        if os.path.getsize(path) > MAX_SCAN_SIZE:
            return

        with self._scan_lock:
            file_hash = sha256_file(path)
            if file_hash:
                ioc = check_ioc(self.console_url, self.token, file_hash, "hash")
                if ioc:
                    self._report({
                        "threat_type": "malware",
                        "severity": ioc.get("severity", "high"),
                        "name": ioc.get("threat_name", "Known Malware"),
                        "description": f"IoC hash match: {file_hash[:16]}...",
                        "file_path": path,
                        "file_hash": file_hash,
                        "action_taken": "detected"
                    })
                    return

            # ClamAV scan
            detected, name = scan_with_clamav(path)
            if detected:
                self._report({
                    "threat_type": "malware",
                    "severity": "high",
                    "name": name,
                    "description": f"ClamAV detection on {event_type}",
                    "file_path": path,
                    "file_hash": file_hash,
                    "action_taken": "detected"
                })
                return

            # YARA scan
            matches = scan_with_yara(path)
            for match in matches:
                severity = "critical" if any(x in match.lower() for x in ("ransomware", "spyware", "predator", "pegasus")) else "high"
                self._report({
                    "threat_type": "spyware" if "spyware" in match.lower() else "malware",
                    "severity": severity,
                    "name": f"YARA: {match}",
                    "description": f"YARA rule matched on file {event_type}",
                    "file_path": path,
                    "file_hash": file_hash,
                    "action_taken": "detected"
                })

    def _report(self, threat: dict):
        report_threat(self.console_url, self.token, threat)

# ── Process Monitor ───────────────────────────────────────────────────────────
SUSPICIOUS_PROCESSES = {
    "vssadmin": ("ransomware", "critical", "VSS deletion attempt (ransomware)"),
    "wbadmin": ("ransomware", "critical", "Backup deletion attempt (ransomware)"),
    "bcdedit": ("ransomware", "high", "Boot config modification (ransomware)"),
}

_seen_pids: set[int] = set()

def monitor_processes(console_url: str, token: str):
    import psutil
    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    pid = proc.info["pid"]
                    if pid in _seen_pids:
                        continue
                    _seen_pids.add(pid)
                    name = (proc.info["name"] or "").lower()
                    cmdline = " ".join(proc.info.get("cmdline") or []).lower()

                    for suspicious, (ttype, severity, desc) in SUSPICIOUS_PROCESSES.items():
                        if suspicious in name or suspicious in cmdline:
                            report_threat(console_url, token, {
                                "threat_type": ttype,
                                "severity": severity,
                                "name": f"Suspicious process: {proc.info['name']}",
                                "description": desc,
                                "process_name": proc.info["name"],
                                "process_pid": pid,
                                "action_taken": "detected"
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            log.error(f"Process monitor error: {e}")
        time.sleep(5)

# ── Console-initiated Scan ────────────────────────────────────────────────────
def run_console_scan(console_url: str, token: str, cmd: dict):
    """Execute a scan ordered by the console and report results back."""
    import time as _time
    scan_type   = cmd.get("scan_type", "quick")
    target_path = cmd.get("target_path", "/")
    start_time  = _time.time()
    files_scanned = 0
    threats_found = 0

    def report(event_type: str, extra: dict = {}):
        try:
            requests.post(
                f"{console_url}/api/scan/report",
                json={"type": event_type, **extra},
                headers={"X-Agent-Token": token},
                verify=False, timeout=10
            )
        except Exception:
            pass

    report("scan_start", {"scan_type": scan_type, "target_path": target_path})

    scan_dirs = {
        "quick": ["/home", "/tmp", "/var/tmp"],
        "full":  ["/home", "/tmp", "/var", "/opt", "/usr/local", "/root"],
        "custom": [target_path],
        "memory": [],
        "rootkit": ["/", "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"],
    }.get(scan_type, [target_path])

    for scan_dir in [d for d in scan_dirs if os.path.isdir(d)]:
        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if not os.path.isfile(fpath) or os.path.getsize(fpath) > 50*1024*1024:
                        continue
                    files_scanned += 1
                    if files_scanned % 100 == 0:
                        report("scan_progress", {"files_scanned": files_scanned, "current_file": fpath})

                    # ClamAV
                    detected, name = scan_with_clamav(fpath)
                    if detected:
                        threats_found += 1
                        report("scan_threat", {
                            "severity": "high", "name": name,
                            "file_path": fpath, "action": "detected"
                        })
                        continue

                    # YARA
                    for match in scan_with_yara(fpath):
                        threats_found += 1
                        sev = "critical" if any(x in match.lower() for x in ("ransomware","spyware")) else "high"
                        report("scan_threat", {
                            "severity": sev, "name": f"YARA:{match}",
                            "file_path": fpath, "action": "detected"
                        })
                except Exception:
                    pass

    duration = _time.time() - start_time
    report("scan_complete", {
        "files_scanned": files_scanned,
        "threats_found": threats_found,
        "duration_seconds": round(duration, 1)
    })
    log.info(f"Scan complete: {files_scanned} files, {threats_found} threats in {duration:.1f}s")


def poll_commands_loop(console_url: str, token: str):
    """Poll console for pending scan/action commands every 15 seconds."""
    while True:
        try:
            resp = requests.get(
                f"{console_url}/api/scan/commands",
                headers={"X-Agent-Token": token},
                verify=False, timeout=10
            )
            data = resp.json()
            for cmd in data.get("commands", []):
                if cmd.get("type") == "scan":
                    threading.Thread(
                        target=run_console_scan,
                        args=(console_url, token, cmd),
                        daemon=True
                    ).start()
        except Exception:
            pass
        time.sleep(15)


# ── Heartbeat ─────────────────────────────────────────────────────────────────
def heartbeat_loop(console_url: str, token: str, interval: int = 60):
    while True:
        try:
            resp = requests.post(
                f"{console_url}/api/endpoints/heartbeat",
                json={"ip_address": get_local_ip()},
                headers={"X-Agent-Token": token},
                verify=False, timeout=10
            )
            data = resp.json()
            if data.get("status") == "pending_approval":
                log.info("Waiting for adoption...")
        except Exception as e:
            log.warning(f"Heartbeat failed: {e}")
        time.sleep(interval)

# ── YARA refresh ──────────────────────────────────────────────────────────────
def yara_refresh_loop(console_url: str, interval: int = 3600):
    while True:
        load_yara_rules(console_url)
        time.sleep(interval)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage: agent_linux.py <console_url>")
        print("Example: agent_linux.py http://192.168.1.100:9000")
        sys.exit(1)

    console_url = sys.argv[1].rstrip("/")
    cfg = load_config()

    # Register if no token
    if not cfg.get("token"):
        log.info(f"Registering with console: {console_url}")
        try:
            result = register(console_url)
            cfg["token"] = result["token"]
            cfg["endpoint_id"] = result["endpoint_id"]
            cfg["console_url"] = console_url
            save_config(cfg)
            log.info(f"Registered as endpoint #{result['endpoint_id']}")
        except Exception as e:
            log.error(f"Registration failed: {e}")
            sys.exit(1)

    token = cfg["token"]
    endpoint_id = cfg["endpoint_id"]

    # Wait for adoption if not yet approved
    wait_for_adoption(console_url, endpoint_id, token)

    # Load YARA rules
    load_yara_rules(console_url)

    # Setup canary files
    canaries = setup_canary_files()
    log.info(f"Canary files created: {len(canaries)}")

    # Start heartbeat thread
    threading.Thread(target=heartbeat_loop, args=(console_url, token), daemon=True).start()

    # Start process monitor thread
    threading.Thread(target=monitor_processes, args=(console_url, token), daemon=True).start()

    # Start YARA refresh thread
    threading.Thread(target=yara_refresh_loop, args=(console_url,), daemon=True).start()

    # Start command polling (scan requests from console)
    threading.Thread(target=poll_commands_loop, args=(console_url, token), daemon=True).start()

    # Start file system monitor
    watch_dirs = ["/home", "/tmp", "/var/tmp", "/opt", "/usr/local/bin", "/usr/bin"]
    watch_dirs = [d for d in watch_dirs if os.path.isdir(d)]

    handler = FileMonitor(console_url, token, canaries)
    observer = Observer()
    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)
        log.info(f"Monitoring: {d}")
    observer.start()

    log.info("AegisEDR Agent running. Press Ctrl+C to stop.")

    def shutdown(sig, frame):
        log.info("Shutting down...")
        observer.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
