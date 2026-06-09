"""
AegisEDR Windows Agent
Monitors the Windows endpoint and reports threats to the console.
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
import ctypes
import tempfile
from pathlib import Path

import requests
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

AGENT_VERSION = "1.0.0"
CONFIG_PATH = r"C:\ProgramData\AegisEDR\config.json"
LOG_PATH = r"C:\ProgramData\AegisEDR\agent.log"

os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("aegisedr")

# ── Config ────────────────────────────────────────────────────────────────────
def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_config(cfg: dict):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

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

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def disable_windows_defender():
    """Disable Defender real-time protection. Requires admin + Tamper Protection off."""
    try:
        import winreg
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                  r"SOFTWARE\Policies\Microsoft\Windows Defender",
                                  0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "DisableAntiVirus",   0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
    except Exception:
        pass
    subprocess.run(
        ["powershell", "-NonInteractive", "-Command",
         "Set-MpPreference -DisableRealtimeMonitoring $true "
         "-DisableIOAVProtection $true -DisableBehaviorMonitoring $true "
         "-ErrorAction SilentlyContinue"],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
    )
    log.info("Windows Defender real-time protection disabled")

def enable_windows_defender():
    """Re-enable Defender real-time protection."""
    try:
        import winreg
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                  r"SOFTWARE\Policies\Microsoft\Windows Defender",
                                  0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "DisableAntiSpyware")
        winreg.DeleteValue(key, "DisableAntiVirus")
        winreg.CloseKey(key)
    except Exception:
        pass
    subprocess.run(
        ["powershell", "-NonInteractive", "-Command",
         "Set-MpPreference -DisableRealtimeMonitoring $false "
         "-DisableIOAVProtection $false -DisableBehaviorMonitoring $false "
         "-ErrorAction SilentlyContinue"],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
    )
    log.info("Windows Defender re-enabled")

# ── Registration ──────────────────────────────────────────────────────────────
def register(console_url: str) -> dict:
    data = {
        "hostname": socket.gethostname(),
        "ip_address": get_local_ip(),
        "os_type": "Windows",
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
            if resp.json().get("approved"):
                log.info("Endpoint adopted! Starting protection...")
                return
            log.info("Still pending adoption...")
        except Exception as e:
            log.warning(f"Console unreachable: {e}")
        time.sleep(30)

# ── Threat reporting ──────────────────────────────────────────────────────────
def report_threat(console_url: str, token: str, threat: dict):
    try:
        requests.post(
            f"{console_url}/api/threats/report",
            json=threat,
            headers={"X-Agent-Token": token},
            verify=False, timeout=10
        )
        log.warning(f"THREAT: [{threat['severity'].upper()}] {threat['name']}")
    except Exception as e:
        log.error(f"Failed to report threat: {e}")

def quarantine_file(console_url: str, token: str, file_path: str, threat_id: int = None):
    try:
        q_dir = r"C:\ProgramData\AegisEDR\Quarantine"
        os.makedirs(q_dir, exist_ok=True)
        q_name = f"{int(time.time())}_{os.path.basename(file_path)}.quar"
        q_path = os.path.join(q_dir, q_name)
        os.rename(file_path, q_path)
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
        log.info(f"Quarantined: {file_path}")
    except Exception as e:
        log.error(f"Quarantine failed: {e}")

# ── YARA Scanner (via yara64.exe subprocess) ──────────────────────────────────
_yara_rules_file: str | None = None
_yara_lock = threading.Lock()

def _yara_exe() -> str | None:
    # PyInstaller bundle: yara64.exe is extracted to _MEIPASS
    candidates = [
        os.path.join(getattr(sys, "_MEIPASS", ""), "yara64.exe"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_bin", "yara64.exe"),
        r"C:\Program Files\AegisEDR Agent\yara64.exe",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None

def load_yara_rules(console_url: str, token: str = ""):
    global _yara_rules_file
    exe = _yara_exe()
    if not exe:
        log.warning("YARA rules load failed: yara64.exe not found")
        return
    try:
        headers = {"X-Agent-Token": token} if token else {}
        resp = requests.get(f"{console_url}/api/yara/export", headers=headers, verify=False, timeout=10)
        if resp.status_code == 200 and resp.text.strip():
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False, encoding="utf-8")
            tmp.write(resp.text)
            tmp.close()
            with _yara_lock:
                _yara_rules_file = tmp.name
            log.info(f"YARA rules loaded ({len(resp.text)} bytes)")
    except Exception as e:
        log.warning(f"YARA rules load failed: {e}")

def scan_with_yara(file_path: str) -> list[str]:
    with _yara_lock:
        rules_file = _yara_rules_file
    if not rules_file or not os.path.isfile(rules_file):
        return []
    exe = _yara_exe()
    if not exe:
        return []
    try:
        result = subprocess.run(
            [exe, rules_file, file_path],
            capture_output=True, text=True, timeout=15
        )
        matches = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if parts:
                matches.append(parts[0])
        return matches
    except Exception:
        return []

# ── IoC Check ─────────────────────────────────────────────────────────────────
_ioc_cache: dict[str, dict] = {}

def check_ioc(console_url: str, token: str, value: str, ioc_type: str) -> dict | None:
    key = f"{ioc_type}:{value}"
    if key in _ioc_cache:
        return _ioc_cache[key]
    try:
        resp = requests.post(
            f"{console_url}/api/ioc/check",
            json={"value": value, "type": ioc_type},
            headers={"X-Agent-Token": token},
            verify=False, timeout=5
        )
        data = resp.json()
        if data.get("found"):
            _ioc_cache[key] = data["threat"]
            return data["threat"]
    except Exception:
        pass
    return None

# ── Anti-Ransomware ───────────────────────────────────────────────────────────
RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypted", ".locky", ".wncry",
    ".wcry", ".wncryt", ".lockbit", ".lb3", ".alphv", ".cerber",
    ".ryuk", ".revil", ".conti", ".blackcat", ".zepto", ".vvv"
}
RANSOM_NOTE_NAMES = {
    "readme.txt", "decrypt_instructions.txt", "how_to_decrypt.txt",
    "restore-my-files.txt", "your_files_are_encrypted.txt",
    "recover_files.txt", "@please_read_me@.txt", "ransom_note.txt"
}

_rename_counter: dict[str, int] = {}
_rename_lock = threading.Lock()

def check_ransomware_behavior(file_path: str) -> str | None:
    fname = os.path.basename(file_path).lower()
    ext = Path(file_path).suffix.lower()

    if ext in RANSOM_EXTENSIONS:
        return f"Ransomware extension: {ext}"

    if fname in RANSOM_NOTE_NAMES:
        return f"Ransom note: {fname}"

    if os.path.exists(file_path) and os.path.getsize(file_path) > 1024:
        entropy = file_entropy(file_path)
        if entropy > 7.8:
            with _rename_lock:
                parent = os.path.dirname(file_path)
                _rename_counter[parent] = _rename_counter.get(parent, 0) + 1
                if _rename_counter[parent] > 20:
                    return f"Mass encryption detected (entropy={entropy:.2f})"
    return None

def setup_canary_files() -> list[str]:
    canary_dirs = [
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Desktop"),
        r"C:\Users\Public\Documents"
    ]
    canaries = []
    for d in canary_dirs:
        if os.path.isdir(d):
            path = os.path.join(d, ".aegisedr_canary_do_not_touch.txt")
            try:
                with open(path, "w") as f:
                    f.write("AegisEDR canary file — do not modify")
                canaries.append(path)
            except Exception:
                pass
    return canaries

# ── File Monitor ──────────────────────────────────────────────────────────────
SCAN_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta",
    ".msi", ".scr", ".com", ".pif", ".jar", ".wsf", ".lnk"
}
SKIP_DIRS = {"Windows\\WinSxS", "Windows\\servicing", "$Recycle.Bin"}
MAX_SCAN_SIZE = 50 * 1024 * 1024

class FileMonitor(FileSystemEventHandler):
    def __init__(self, console_url: str, token: str, canaries: list[str]):
        self.console_url = console_url
        self.token = token
        self.canaries = set(canaries)
        self._lock = threading.Semaphore(4)

    def on_created(self, event):
        if not event.is_directory:
            threading.Thread(target=self._handle, args=(event.src_path,), daemon=True).start()

    def on_modified(self, event):
        if not event.is_directory:
            threading.Thread(target=self._handle, args=(event.src_path,), daemon=True).start()

    def _handle(self, path: str):
        if not os.path.isfile(path):
            return
        for skip in SKIP_DIRS:
            if skip in path:
                return

        if path in self.canaries:
            self._report({
                "threat_type": "ransomware",
                "severity": "critical",
                "name": "Ransomware Canary Triggered",
                "description": f"Canary modified: {path}",
                "file_path": path,
                "action_taken": "alert"
            })
            return

        ransom = check_ransomware_behavior(path)
        if ransom:
            self._report({
                "threat_type": "ransomware",
                "severity": "critical",
                "name": "Ransomware Activity Detected",
                "description": ransom,
                "file_path": path,
                "action_taken": "alert"
            })
            return

        ext = Path(path).suffix.lower()
        if ext not in SCAN_EXTENSIONS:
            return
        try:
            if os.path.getsize(path) > MAX_SCAN_SIZE:
                return
        except Exception:
            return

        with self._lock:
            file_hash = sha256_file(path)
            if file_hash:
                ioc = check_ioc(self.console_url, self.token, file_hash, "hash")
                if ioc:
                    self._report({
                        "threat_type": "malware",
                        "severity": ioc.get("severity", "high"),
                        "name": ioc.get("threat_name", "Known Malware"),
                        "description": "IoC hash match",
                        "file_path": path,
                        "file_hash": file_hash,
                        "action_taken": "detected"
                    })
                    return

            matches = scan_with_yara(path)
            for m in matches:
                sev = "critical" if any(x in m.lower() for x in ("ransomware","spyware","predator","pegasus")) else "high"
                ttype = "spyware" if "spyware" in m.lower() else "malware"
                self._report({
                    "threat_type": ttype,
                    "severity": sev,
                    "name": f"YARA: {m}",
                    "description": "YARA rule matched",
                    "file_path": path,
                    "file_hash": file_hash,
                    "action_taken": "detected"
                })

    def _report(self, threat: dict):
        report_threat(self.console_url, self.token, threat)

# ── Process Monitor ───────────────────────────────────────────────────────────
SUSPICIOUS_CMD = {
    "vssadmin delete": ("ransomware", "critical", "VSS deletion (ransomware)"),
    "wmic shadowcopy delete": ("ransomware", "critical", "Shadow copy deletion"),
    "bcdedit /set": ("ransomware", "high", "Boot config tampering"),
    "wbadmin delete": ("ransomware", "critical", "Backup deletion"),
    "taskkill /f": ("ransomware", "medium", "Forced process termination"),
}

_seen_pids: set[int] = set()

def monitor_processes(console_url: str, token: str):
    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    pid = proc.info["pid"]
                    if pid in _seen_pids:
                        continue
                    _seen_pids.add(pid)
                    cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                    for pattern, (ttype, sev, desc) in SUSPICIOUS_CMD.items():
                        if pattern in cmdline:
                            report_threat(console_url, token, {
                                "threat_type": ttype,
                                "severity": sev,
                                "name": f"Suspicious command: {proc.info['name']}",
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
    import time as _time
    scan_type   = cmd.get("scan_type", "quick")
    target_path = cmd.get("target_path", r"C:\Users")
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
        "quick":   [os.path.expanduser("~"), r"C:\Windows\Temp", r"C:\Temp"],
        "full":    [r"C:\Users", r"C:\Windows\Temp", r"C:\ProgramData"],
        "custom":  [target_path],
        "memory":  [],
        "rootkit": [r"C:\Windows\System32", r"C:\Windows\SysWOW64"],
    }.get(scan_type, [target_path])

    for scan_dir in [d for d in scan_dirs if os.path.isdir(d)]:
        for root, dirs, files in os.walk(scan_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if not os.path.isfile(fpath) or os.path.getsize(fpath) > 50*1024*1024:
                        continue
                    files_scanned += 1
                    if files_scanned % 100 == 0:
                        report("scan_progress", {"files_scanned": files_scanned, "current_file": fpath})

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
    while True:
        try:
            resp = requests.get(
                f"{console_url}/api/scan/commands",
                headers={"X-Agent-Token": token},
                verify=False, timeout=10
            )
            for cmd in resp.json().get("commands", []):
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
def heartbeat_loop(console_url: str, token: str):
    while True:
        try:
            resp = requests.post(
                f"{console_url}/api/endpoints/heartbeat",
                json={"ip_address": get_local_ip()},
                headers={"X-Agent-Token": token},
                verify=False, timeout=10
            )
        except Exception as e:
            log.warning(f"Heartbeat failed: {e}")
        time.sleep(60)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage: agent_windows.py <console_url>")
        sys.exit(1)

    console_url = sys.argv[1].rstrip("/")
    cfg = load_config()

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

    wait_for_adoption(console_url, endpoint_id, token)

    if is_admin():
        disable_windows_defender()

    load_yara_rules(console_url, token)

    canaries = setup_canary_files()
    log.info(f"Canary files: {len(canaries)}")

    threading.Thread(target=heartbeat_loop, args=(console_url, token), daemon=True).start()
    threading.Thread(target=monitor_processes, args=(console_url, token), daemon=True).start()
    threading.Thread(target=lambda: [time.sleep(3600) or load_yara_rules(console_url, token) for _ in iter(int, 1)], daemon=True).start()
    threading.Thread(target=poll_commands_loop, args=(console_url, token), daemon=True).start()

    # Monitor key Windows directories
    watch_dirs = [
        os.path.expanduser("~"),
        r"C:\Users\Public",
        r"C:\Windows\Temp",
        r"C:\Temp",
    ]
    watch_dirs = [d for d in watch_dirs if os.path.isdir(d)]

    handler = FileMonitor(console_url, token, canaries)
    observer = Observer()
    for d in watch_dirs:
        observer.schedule(handler, d, recursive=True)
        log.info(f"Monitoring: {d}")
    observer.start()

    log.info("AegisEDR Windows Agent running.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
