#!/usr/bin/env python3
"""
AegisEDR Linux Agent
Monitors the endpoint and reports threats to the console.
"""
import logging
import os
import platform
import signal
import socket
import sys
import threading
import time
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import edr_common

CONFIG_PATH = "/etc/aegisedr-agent/config.json"
IOC_PATH = "/var/lib/aegisedr-agent/ioc_cache.json"
AGENT_VERSION = "1.1.0"
CFG: dict = {}
POLICY = {"auto_quarantine": "1", "auto_block_ransomware": "1"}
IOC = edr_common.IocCache(IOC_PATH)

_handlers = [logging.StreamHandler()]
try:
    _handlers.insert(0, logging.FileHandler("/var/log/aegisedr-agent.log"))
except OSError:
    pass
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=_handlers)
log = logging.getLogger("aegisedr")


def load_config() -> dict:
    return edr_common.load_json(CONFIG_PATH)


def save_config(cfg: dict):
    edr_common.save_json(CONFIG_PATH, cfg)


def headers(token: str) -> dict:
    return {"X-Agent-Token": token}


def register(console_url: str, enrollment_code: str) -> dict:
    data = {
        "hostname": socket.gethostname(),
        "os_type": "Linux",
        "os_version": platform.version()[:80],
        "agent_version": AGENT_VERSION,
        "enrollment_code": enrollment_code,
    }
    resp = edr_common.http(
        "POST", f"{console_url}/api/endpoints/register", CFG, json=data, timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def reregister(console_url: str, token: str):
    data = {
        "hostname": socket.gethostname(),
        "os_type": "Linux",
        "os_version": platform.version()[:80],
        "agent_version": AGENT_VERSION,
    }
    edr_common.http(
        "POST", f"{console_url}/api/endpoints/register", CFG,
        json=data, headers=headers(token), timeout=10,
    )


def wait_for_adoption(console_url: str, endpoint_id: int, token: str):
    log.info("Waiting for admin adoption on the console")
    while True:
        try:
            resp = edr_common.http(
                "GET", f"{console_url}/api/endpoints/{endpoint_id}/status", CFG,
                headers=headers(token), timeout=10,
            )
            if resp.json().get("approved"):
                log.info("Endpoint adopted")
                return
            log.info("Still pending adoption")
        except Exception as exc:
            log.warning("Console unreachable: %s", exc)
        time.sleep(30)


def report_threat(console_url: str, token: str, threat: dict):
    try:
        edr_common.http(
            "POST", f"{console_url}/api/threats/report", CFG,
            json=threat, headers=headers(token), timeout=10,
        )
        log.warning("THREAT [%s] %s", threat.get("severity", "").upper(), threat.get("name"))
    except Exception as exc:
        log.error("Failed to report threat: %s", exc)


def quarantine_file(console_url: str, token: str, file_path: str):
    try:
        dest, digest, size = edr_common.quarantine_move(file_path, windows=False)
        edr_common.http(
            "POST", f"{console_url}/api/quarantine/add", CFG,
            json={
                "original_path": file_path,
                "quarantine_path": dest,
                "file_hash": digest,
                "file_size": size,
            },
            headers=headers(token), timeout=10,
        )
        log.info("Quarantined %s", file_path)
    except Exception as exc:
        log.error("Quarantine failed for %s: %s", file_path, exc)


_yara_rules = None
_yara_lock = threading.Lock()


def load_yara_rules(console_url: str, token: str):
    global _yara_rules
    try:
        import yara
        resp = edr_common.http(
            "GET", f"{console_url}/api/yara/export", CFG,
            headers=headers(token), timeout=20,
        )
        if resp.status_code == 200 and resp.text.strip():
            rules = yara.compile(source=resp.text)
            with _yara_lock:
                _yara_rules = rules
            log.info("YARA rules loaded from console")
    except Exception as exc:
        log.warning("YARA rules load failed: %s", exc)


def scan_with_yara(file_path: str) -> list[str]:
    with _yara_lock:
        rules = _yara_rules
    if not rules:
        return []
    try:
        return [match.rule for match in rules.match(file_path, timeout=10)]
    except Exception:
        return []


def refresh_iocs(console_url: str, token: str):
    try:
        resp = edr_common.http(
            "GET", f"{console_url}/api/ioc/export", CFG,
            headers=headers(token), timeout=120,
        )
        if resp.status_code == 200:
            IOC.replace(resp.json().get("entries") or [])
            log.info("IoC cache refreshed (%s entries)", len(IOC.entries))
    except Exception as exc:
        log.warning("IoC refresh failed: %s", exc)


SKIP_EXTENSIONS = {".log", ".tmp", ".swp", ".pyc", ".sock", ".pid"}
SCAN_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".sh",
    ".py", ".elf", ".bin", ".msi", ".jar", ".apk", ".deb", ".rpm",
}
MAX_SCAN_SIZE = 50 * 1024 * 1024


class FileMonitor(FileSystemEventHandler):
    def __init__(self, console_url: str, token: str, canaries: list[str]):
        self.console_url = console_url
        self.token = token
        self.canaries = set(os.path.realpath(path) for path in canaries)
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
        real = os.path.realpath(path)
        if real in self.canaries:
            self._report({
                "threat_type": "ransomware",
                "severity": "critical",
                "name": "Ransomware Canary Triggered",
                "description": f"Canary file modified: {path}",
                "file_path": path,
                "action_taken": "alert",
            })
            return
        ext = Path(path).suffix.lower()
        if ext in SKIP_EXTENSIONS:
            return
        ransom = edr_common.check_ransomware(path)
        if ransom:
            self._report({
                "threat_type": "ransomware",
                "severity": "critical",
                "name": "Ransomware Activity Detected",
                "description": ransom,
                "file_path": path,
                "action_taken": "quarantined" if POLICY.get("auto_quarantine") == "1" else "alert",
            })
            if POLICY.get("auto_quarantine") == "1":
                quarantine_file(self.console_url, self.token, path)
            return
        if ext not in SCAN_EXTENSIONS:
            return
        try:
            if os.path.getsize(path) > MAX_SCAN_SIZE:
                return
        except OSError:
            return
        with self._scan_lock:
            self._scan_executable(path, event_type)

    def _scan_executable(self, path: str, event_type: str):
        file_hash = edr_common.sha256_file(path)
        if file_hash:
            ioc = IOC.lookup("hash", file_hash)
            if ioc:
                self._act(path, {
                    "threat_type": "malware",
                    "severity": ioc.get("severity", "high"),
                    "name": ioc.get("threat_name") or "Known Malware",
                    "description": "IoC hash match",
                    "file_path": path,
                    "file_hash": file_hash,
                    "action_taken": "detected",
                })
                return
        detected, name = edr_common.clamd_scan(path)
        if detected:
            self._act(path, {
                "threat_type": "malware",
                "severity": "high",
                "name": name,
                "description": f"ClamAV detection on {event_type}",
                "file_path": path,
                "file_hash": file_hash,
                "action_taken": "detected",
            })
            return
        for match in scan_with_yara(path):
            severity = "critical" if any(x in match.lower() for x in ("ransomware", "spyware", "predator", "pegasus")) else "high"
            self._act(path, {
                "threat_type": "spyware" if "spyware" in match.lower() else "malware",
                "severity": severity,
                "name": f"YARA: {match}",
                "description": f"YARA rule matched on file {event_type}",
                "file_path": path,
                "file_hash": file_hash,
                "action_taken": "detected",
            })

    def _act(self, path: str, threat: dict):
        if POLICY.get("auto_quarantine") == "1":
            threat["action_taken"] = "quarantined"
            self._report(threat)
            quarantine_file(self.console_url, self.token, path)
        else:
            self._report(threat)

    def _report(self, threat: dict):
        report_threat(self.console_url, self.token, threat)


def monitor_processes(console_url: str, token: str):
    tracker = edr_common.ProcessTracker()
    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
                try:
                    pid = proc.info["pid"]
                    if not tracker.is_new(pid, proc.info.get("create_time")):
                        continue
                    reason = edr_common.suspicious_image(proc.info.get("exe") or "")
                    if not reason:
                        continue
                    report_threat(console_url, token, {
                        "threat_type": "malware",
                        "severity": "high",
                        "name": f"Suspicious process: {proc.info.get('name')}",
                        "description": reason,
                        "process_name": proc.info.get("name"),
                        "process_pid": pid,
                        "action_taken": "detected",
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as exc:
            log.error("Process monitor error: %s", exc)
        time.sleep(5)


def setup_canary_files() -> list[str]:
    canaries = []
    for directory in (os.path.expanduser("~/Documents"), os.path.expanduser("~/Desktop")):
        if not os.path.isdir(directory):
            continue
        path = os.path.join(directory, ".aegisedr_canary_do_not_touch")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, b"AegisEDR canary file - do not modify\n")
            finally:
                os.close(fd)
            canaries.append(path)
        except OSError:
            pass
    return canaries


def run_console_scan(console_url: str, token: str, cmd: dict):
    payload = cmd.get("payload") or {}
    scan_type = payload.get("scan_type") or cmd.get("scan_type") or "quick"
    target_path = payload.get("target_path") or cmd.get("target_path") or "/"
    job_id = payload.get("scan_job_id") or cmd.get("scan_job_id")
    command_id = cmd.get("id")
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    files_scanned = 0
    threats_found = 0

    def report(event_type: str, extra: dict | None = None):
        body = {"type": event_type, "command_id": command_id, "scan_job_id": job_id}
        if extra:
            body.update(extra)
        try:
            edr_common.http(
                "POST", f"{console_url}/api/scan/report", CFG,
                json=body, headers=headers(token), timeout=10,
            )
        except Exception:
            pass

    def finish(status: str, detail: str):
        if not command_id:
            return
        try:
            edr_common.http(
                "POST", f"{console_url}/api/agent/commands/{command_id}/result", CFG,
                json={"status": status, "detail": detail}, headers=headers(token), timeout=10,
            )
        except Exception:
            pass

    report("scan_start", {"scan_type": scan_type, "target_path": target_path})
    try:
        if scan_type == "memory":
            threats_found, files_scanned = _scan_process_images(report)
        elif scan_type == "rootkit":
            threats_found, files_scanned = _scan_rootkit_signals(report)
        else:
            threats_found, files_scanned = _scan_directories(scan_type, target_path, report)
        report("scan_complete", {
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "started_at": started,
            "duration_seconds": 0,
        })
        finish("done", f"scanned={files_scanned} threats={threats_found}")
    except Exception as exc:
        log.error("Scan failed: %s", exc)
        finish("failed", str(exc)[:400])


def _scan_process_images(report) -> tuple[int, int]:
    found = 0
    checked = 0
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        checked += 1
        reason = edr_common.suspicious_image(proc.info.get("exe") or "")
        if not reason:
            continue
        found += 1
        report("scan_threat", {
            "severity": "high",
            "name": f"Suspicious process: {proc.info.get('name')}",
            "file_path": proc.info.get("exe") or "",
            "action": "detected",
        })
    return found, checked


def _scan_rootkit_signals(report) -> tuple[int, int]:
    found = 0
    for pid in edr_common.hidden_user_pids():
        found += 1
        report("scan_threat", {
            "severity": "critical",
            "name": f"Hidden process {pid}",
            "file_path": f"/proc/{pid}",
            "action": "detected",
        })
    preload = "/etc/ld.so.preload"
    if os.path.isfile(preload) and os.path.getsize(preload) > 0:
        found += 1
        report("scan_threat", {
            "severity": "high",
            "name": "ld.so.preload is not empty",
            "file_path": preload,
            "action": "detected",
        })
    return found, found


def _scan_directories(scan_type: str, target_path: str, report) -> tuple[int, int]:
    scan_dirs = {
        "quick": ["/home", "/tmp", "/var/tmp"],
        "full": ["/home", "/tmp", "/var", "/opt", "/usr/local", "/root"],
        "custom": [target_path],
    }.get(scan_type, [target_path])
    files_scanned = 0
    threats_found = 0
    for scan_dir in [d for d in scan_dirs if os.path.isdir(d)]:
        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if not os.path.isfile(fpath) or os.path.getsize(fpath) > MAX_SCAN_SIZE:
                        continue
                    ext = Path(fpath).suffix.lower()
                    if ext and ext not in SCAN_EXTENSIONS:
                        continue
                    files_scanned += 1
                    if files_scanned % 100 == 0:
                        report("scan_progress", {"files_scanned": files_scanned, "current_file": fpath})
                    detected, name = edr_common.clamd_scan(fpath)
                    if detected:
                        threats_found += 1
                        report("scan_threat", {"severity": "high", "name": name, "file_path": fpath, "action": "detected"})
                        continue
                    for match in scan_with_yara(fpath):
                        threats_found += 1
                        severity = "critical" if any(x in match.lower() for x in ("ransomware", "spyware")) else "high"
                        report("scan_threat", {"severity": severity, "name": f"YARA:{match}", "file_path": fpath, "action": "detected"})
                except Exception:
                    pass
    return threats_found, files_scanned


def handle_command(console_url: str, token: str, cmd: dict):
    kind = cmd.get("command") or cmd.get("type")
    payload = cmd.get("payload") or {}
    if kind == "scan":
        threading.Thread(target=run_console_scan, args=(console_url, token, cmd), daemon=True).start()
        return
    command_id = cmd.get("id")
    status, detail = "done", "ok"
    try:
        if kind == "quarantine":
            quarantine_file(console_url, token, payload.get("file_path") or "")
        elif kind == "restore":
            edr_common.restore_quarantined(payload["quarantine_path"], payload["original_path"], windows=False)
        elif kind == "purge":
            edr_common.purge_quarantined(payload["quarantine_path"], windows=False)
        else:
            status, detail = "failed", f"unknown command {kind}"
    except Exception as exc:
        status, detail = "failed", str(exc)[:400]
        log.error("Command %s failed: %s", kind, exc)
    if command_id:
        try:
            edr_common.http(
                "POST", f"{console_url}/api/agent/commands/{command_id}/result", CFG,
                json={"status": status, "detail": detail}, headers=headers(token), timeout=10,
            )
        except Exception as exc:
            log.error("Could not report command result: %s", exc)


def poll_commands_loop(console_url: str, token: str):
    while True:
        try:
            resp = edr_common.http(
                "GET", f"{console_url}/api/agent/commands", CFG,
                headers=headers(token), timeout=10,
            )
            for cmd in resp.json().get("commands", []):
                handle_command(console_url, token, cmd)
        except Exception:
            pass
        time.sleep(15)


def heartbeat_loop(console_url: str, token: str):
    while True:
        try:
            resp = edr_common.http(
                "POST", f"{console_url}/api/endpoints/heartbeat", CFG,
                json={}, headers=headers(token), timeout=10,
            )
            data = resp.json()
            if isinstance(data.get("policy"), dict):
                POLICY.update(data["policy"])
            if data.get("status") == "pending_approval":
                log.info("Waiting for adoption")
        except Exception as exc:
            log.warning("Heartbeat failed: %s", exc)
        try:
            interval = int(POLICY.get("agent_heartbeat_interval") or 60)
        except ValueError:
            interval = 60
        time.sleep(min(max(interval, 15), 3600))


def refresh_loop(console_url: str, token: str):
    while True:
        load_yara_rules(console_url, token)
        refresh_iocs(console_url, token)
        time.sleep(3600)


def parse_args(argv: list[str]):
    if len(argv) < 2:
        print("Usage: agent_linux.py <console_url> [--enroll CODE] [--ca CERT]")
        sys.exit(1)
    url = argv[1].rstrip("/")
    enroll = None
    ca = None
    index = 2
    while index < len(argv):
        if argv[index] == "--enroll" and index + 1 < len(argv):
            enroll = argv[index + 1]
            index += 2
        elif argv[index] == "--ca" and index + 1 < len(argv):
            ca = argv[index + 1]
            index += 2
        else:
            index += 1
    return url, enroll, ca


def main():
    global CFG
    console_url, enroll, ca = parse_args(sys.argv)
    CFG = load_config()
    CFG["console_url"] = console_url
    if ca:
        CFG["ca_cert"] = ca
    if enroll:
        CFG["enrollment_code"] = enroll

    if not CFG.get("token"):
        code = CFG.get("enrollment_code")
        if not code:
            log.error("No agent token and no enrollment code. Pass --enroll CODE.")
            sys.exit(1)
        log.info("Registering with %s", console_url)
        try:
            result = register(console_url, code)
        except Exception as exc:
            log.error("Registration failed: %s", exc)
            sys.exit(1)
        CFG["token"] = result["token"]
        CFG["endpoint_id"] = result["endpoint_id"]
        CFG.pop("enrollment_code", None)
        save_config(CFG)
        log.info("Registered as endpoint #%s", result["endpoint_id"])
    else:
        try:
            reregister(console_url, CFG["token"])
        except Exception as exc:
            log.warning("Re-registration failed: %s", exc)

    token = CFG["token"]
    endpoint_id = CFG["endpoint_id"]
    wait_for_adoption(console_url, endpoint_id, token)
    load_yara_rules(console_url, token)
    refresh_iocs(console_url, token)
    canaries = setup_canary_files()
    log.info("Canary files created: %s", len(canaries))

    threading.Thread(target=heartbeat_loop, args=(console_url, token), daemon=True).start()
    threading.Thread(target=monitor_processes, args=(console_url, token), daemon=True).start()
    threading.Thread(target=refresh_loop, args=(console_url, token), daemon=True).start()
    threading.Thread(target=poll_commands_loop, args=(console_url, token), daemon=True).start()

    watch_dirs = [d for d in ("/home", "/tmp", "/var/tmp", "/opt", "/usr/local/bin") if os.path.isdir(d)]
    handler = FileMonitor(console_url, token, canaries)
    observer = Observer()
    for directory in watch_dirs:
        observer.schedule(handler, directory, recursive=True)
        log.info("Monitoring %s", directory)
    observer.start()
    log.info("AegisEDR agent running")

    def shutdown(sig, frame):
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
