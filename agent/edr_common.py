"""Shared helpers for the AegisEDR endpoint agents.

Imported from the same directory as the agent script. TLS verification is
always on: either the pinned console certificate or the system trust store.
"""
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import threading
import time

import requests

RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypted", ".locky", ".zepto",
    ".cerber", ".wncry", ".wcry", ".wncryt", ".lockbit", ".lb3", ".alphv",
    ".ryuk", ".revil", ".conti", ".blackcat",
}
RANSOM_NOTE_NAMES = {
    "decrypt_instructions.txt", "how_to_decrypt.txt",
    "restore-my-files.txt", "your_files_are_encrypted.txt",
    "recover_files.txt", "ransom_note.txt", "@please_read_me@.txt",
}
BENIGN_ENTROPY_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mkv", ".avi",
    ".zip", ".gz", ".tgz", ".7z", ".rar", ".pdf", ".docx", ".xlsx",
    ".pptx", ".woff", ".woff2", ".ttf", ".otf", ".pyc", ".pack", ".jar",
}

_entropy_hits: dict[str, list] = {}
_entropy_lock = threading.Lock()
ENTROPY_WINDOW = 60
ENTROPY_BURST = 20


def tls_verify(cfg: dict):
    ca = (cfg or {}).get("ca_cert") or os.environ.get("AEGISEDR_CA", "")
    if ca:
        if not os.path.isfile(ca):
            raise RuntimeError(f"Console CA certificate was not found: {ca}")
        return ca
    return True


def http(method: str, url: str, cfg: dict, **kwargs):
    kwargs["verify"] = tls_verify(cfg)
    kwargs.setdefault("timeout", 10)
    return requests.request(method, url, **kwargs)


def save_json(path: str, data, mode: int = 0o600):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    payload = json.dumps(data, indent=2).encode()
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def sha256_file(path: str) -> str:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while chunk := handle.read(65536):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def file_entropy(path: str) -> float:
    try:
        import math
        with open(path, "rb") as handle:
            data = handle.read(65536)
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    except OSError:
        return 0.0


def check_ransomware(path: str) -> str | None:
    """Known-bad extension, a specific ransom-note name, or a short burst of high-entropy files.

    Compressed and media types are ignored for the entropy burst. The counter
    only remembers the last minute, so a folder of old archives does not stay hot.
    """
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if ext in RANSOM_EXTENSIONS:
        return f"Ransomware extension: {ext}"
    if name in RANSOM_NOTE_NAMES:
        return f"Ransom note: {name}"
    if ext in BENIGN_ENTROPY_EXT:
        return None
    try:
        if os.path.getsize(path) < 4096:
            return None
    except OSError:
        return None
    if file_entropy(path) < 7.9:
        return None
    parent = os.path.dirname(path) or "."
    now = time.time()
    with _entropy_lock:
        hits = [stamp for stamp in _entropy_hits.get(parent, []) if now - stamp < ENTROPY_WINDOW]
        hits.append(now)
        _entropy_hits[parent] = hits
        if len(_entropy_hits) > 10000:
            _entropy_hits.clear()
            _entropy_hits[parent] = hits
        if len(hits) >= ENTROPY_BURST:
            return f"Burst of high-entropy files in {parent} ({len(hits)} in {ENTROPY_WINDOW}s)"
    return None


class ProcessTracker:
    """Remember pid plus create time so a recycled pid is inspected again."""

    def __init__(self):
        self._seen: dict[int, float] = {}

    def is_new(self, pid: int, create_time: float | None) -> bool:
        stamp = float(create_time or 0)
        if self._seen.get(pid) == stamp:
            return False
        self._seen[pid] = stamp
        if len(self._seen) > 20000:
            self._seen.clear()
            self._seen[pid] = stamp
        return True


def suspicious_image(exe: str) -> str | None:
    if not exe:
        return None
    lowered = exe.replace("\\", "/").lower()
    if lowered.endswith(" (deleted)"):
        return "Process image was deleted from disk"
    for prefix in ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"):
        if exe.startswith(prefix):
            return f"Process image is under {prefix}"
    if "/temp/" in lowered or lowered.startswith("c:/windows/temp/"):
        return "Process image is in a temp directory"
    return None


def windows_command_reason(cmdline: str) -> str | None:
    text = (cmdline or "").lower()
    checks = (
        (("vssadmin", "delete", "shadow"), "Volume shadow copy deletion"),
        (("wmic", "shadowcopy", "delete"), "Volume shadow copy deletion"),
        (("wbadmin", "delete"), "Backup catalog deletion"),
        (("bcdedit", "recoveryenabled"), "Boot recovery configuration change"),
    )
    for needles, reason in checks:
        if all(needle in text for needle in needles):
            return reason
    return None


def hidden_user_pids() -> list[int]:
    """Pids present in /proc with a userspace image that ps does not list."""
    if not os.path.isdir("/proc"):
        return []
    proc = {int(name) for name in os.listdir("/proc") if name.isdigit()}
    try:
        listed = subprocess.run(
            ["ps", "-eo", "pid="], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    visible = {int(part) for part in listed.stdout.split() if part.isdigit()}
    hidden = []
    for pid in sorted(proc - visible):
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            continue
        if exe:
            hidden.append(pid)
    return hidden


def clamd_scan(path: str) -> tuple[bool, str]:
    """Scan one file through clamd. Returns (False, '') when clamd is not running."""
    for sock_path in ("/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl", "/tmp/clamd.socket"):
        if os.path.exists(sock_path):
            try:
                return _clamd_unix(sock_path, path)
            except OSError:
                continue
    try:
        return _clamd_tcp("127.0.0.1", 3310, path)
    except OSError:
        return False, ""


def _clamd_unix(sock_path: str, path: str) -> tuple[bool, str]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(30)
        client.connect(sock_path)
        return _clamd_instream(client, path)
    finally:
        client.close()


def _clamd_tcp(host: str, port: int, path: str) -> tuple[bool, str]:
    client = socket.create_connection((host, port), timeout=5)
    try:
        client.settimeout(30)
        return _clamd_instream(client, path)
    finally:
        client.close()


def _clamd_instream(client: socket.socket, path: str) -> tuple[bool, str]:
    client.sendall(b"zINSTREAM\0")
    with open(path, "rb") as handle:
        while chunk := handle.read(65536):
            client.sendall(struct.pack("!I", len(chunk)) + chunk)
    client.sendall(struct.pack("!I", 0))
    data = b""
    while b"\0" not in data and b"\n" not in data:
        part = client.recv(4096)
        if not part:
            break
        data += part
    text = data.decode(errors="replace").strip("\0\n ")
    if text.endswith("FOUND"):
        name = text.split(":", 1)[-1].replace("FOUND", "").strip()
        return True, name or "ClamAV"
    return False, ""


class IocCache:
    def __init__(self, path: str):
        self.path = path
        self.entries: dict[tuple[str, str], dict] = {}
        self._load()

    def _load(self):
        data = load_json(self.path)
        for item in data.get("entries") or []:
            kind = item.get("ioc_type") or ""
            value = (item.get("value") or "").lower()
            if kind and value:
                self.entries[(kind, value)] = item

    def replace(self, entries: list):
        self.entries = {}
        stored = []
        for item in entries:
            kind = item.get("ioc_type") or ""
            value = (item.get("value") or "").lower()
            if not kind or not value:
                continue
            kept = {
                "ioc_type": kind,
                "value": value,
                "threat_name": item.get("threat_name") or "",
                "severity": item.get("severity") or "medium",
                "source": item.get("source") or "",
            }
            self.entries[(kind, value)] = kept
            stored.append(kept)
        save_json(self.path, {"entries": stored})

    def lookup(self, kind: str, value: str):
        if not value:
            return None
        return self.entries.get((kind, value.lower()))


def quarantine_root(windows: bool) -> str:
    if windows:
        return r"C:\ProgramData\AegisEDR\Quarantine"
    return "/var/lib/aegisedr-agent/quarantine"


def _inside(path: str, root: str) -> bool:
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(path)
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def quarantine_move(file_path: str, windows: bool) -> tuple[str, str, int]:
    root = quarantine_root(windows)
    os.makedirs(root, exist_ok=True)
    source = os.path.realpath(file_path)
    if _inside(source, root):
        raise RuntimeError("file is already inside quarantine")
    destination = os.path.join(root, f"{int(time.time())}_{os.path.basename(file_path)}.quar")
    shutil.move(source, destination)
    digest = sha256_file(destination)
    size = os.path.getsize(destination)
    try:
        os.chmod(destination, 0o000)
    except OSError:
        pass
    return destination, digest, size, digest


def restore_quarantined(quarantine_path: str, original_path: str, windows: bool):
    root = quarantine_root(windows)
    if not _inside(quarantine_path, root):
        raise RuntimeError("refusing to restore a path outside quarantine")
    if _inside(original_path, root):
        raise RuntimeError("refusing to restore into the quarantine directory")
    try:
        os.chmod(quarantine_path, 0o600)
    except OSError:
        pass
    parent = os.path.dirname(original_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    shutil.move(quarantine_path, original_path)


def purge_quarantined(quarantine_path: str, windows: bool):
    root = quarantine_root(windows)
    if not _inside(quarantine_path, root):
        raise RuntimeError("refusing to delete a path outside quarantine")
    try:
        os.chmod(quarantine_path, 0o600)
    except OSError:
        pass
    os.remove(quarantine_path)
