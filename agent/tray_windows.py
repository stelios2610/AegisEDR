"""
AegisEDR Windows System Tray Monitor
Shows agent status in system tray with right-click menu.
Build: pyinstaller --onefile --noconsole --name AegisEDR-Tray --icon ../assets/icon.ico tray_windows.py
"""
import os
import sys
import json
import ctypes
import threading
import subprocess
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
except ImportError:
    os.system(f"{sys.executable} -m pip install pystray Pillow")
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw

import requests

CONFIG_PATH = r"C:\ProgramData\AegisEDR\config.json"
LOG_PATH    = r"C:\ProgramData\AegisEDR\agent.log"
YARA_EXE_CANDIDATES = [
    os.path.join(getattr(sys, "_MEIPASS", ""), "yara64.exe"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_bin", "yara64.exe"),
    r"C:\Program Files\AegisEDR Agent\yara64.exe",
]

# ── Admin check ───────────────────────────────────────────────────────────────
def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

IS_ADMIN = _is_admin()

# ── Status ────────────────────────────────────────────────────────────────────
STATUS_COLORS = {
    "protected":    (99,  102, 241),
    "pending":      (234, 179,   8),
    "disconnected": (148, 163, 184),
    "threat":       (239,  68,  68),
    "disabled":     (100, 100, 100),
}

_current_status = "disconnected"
_threat_count   = 0
_console_url    = ""
_protection_enabled = True

def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def get_status() -> tuple[str, int]:
    global _console_url
    cfg = load_config()
    _console_url = cfg.get("console_url", "")
    token = cfg.get("token", "")
    if not _protection_enabled:
        return "disabled", 0
    if not _console_url or not token:
        return "disconnected", 0
    try:
        resp = requests.get(
            f"{_console_url}/api/stats",
            headers={"Authorization": f"Bearer {token}"},
            verify=False, timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            threats = sum(data.get("threats_by_severity", {}).values())
            return ("threat", threats) if threats > 0 else ("protected", 0)
        elif resp.status_code == 401:
            return "pending", 0
    except Exception:
        pass
    return "disconnected", 0

# ── Icon generation ───────────────────────────────────────────────────────────
def make_icon(color: tuple, badge: int = 0, disabled: bool = False) -> Image.Image:
    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = size // 2, size // 2

    shield = [
        (cx, 4),
        (cx + 26, 14), (cx + 26, 34),
        (cx + 18, 50), (cx, 60),
        (cx - 18, 50), (cx - 26, 34),
        (cx - 26, 14),
    ]
    draw.polygon(shield, fill=color + (255,))
    inner = [(x * 0.82 + cx * 0.18, y * 0.82 + cy * 0.18) for x, y in shield]
    draw.polygon(inner, fill=(255, 255, 255, 30))

    if disabled:
        # Red X over shield
        draw.line([(cx - 12, cy - 12), (cx + 12, cy + 12)], fill=(220, 50, 50, 255), width=5)
        draw.line([(cx + 12, cy - 12), (cx - 12, cy + 12)], fill=(220, 50, 50, 255), width=5)
    else:
        draw.text((cx - 9, cy - 16), "A", fill=(255, 255, 255, 240), font=None)

    if badge > 0:
        draw.ellipse([44, 44, 60, 60], fill=(239, 68, 68, 255))
        label = str(badge) if badge < 10 else "!"
        draw.text((48 if badge < 10 else 47, 46), label, fill=(255, 255, 255, 255))

    return img

def get_icon_image() -> Image.Image:
    color = STATUS_COLORS.get(_current_status, STATUS_COLORS["disconnected"])
    disabled = (_current_status == "disabled")
    return make_icon(color, _threat_count if _current_status == "threat" else 0, disabled)

# ── Menu actions ──────────────────────────────────────────────────────────────
def open_app(icon=None, it=None):
    """Open the native AegisEDR dashboard window."""
    def _launch():
        app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_windows.py")
        if os.path.isfile(app_path):
            subprocess.Popen(
                [sys.executable, app_path],
                creationflags=subprocess.CREATE_NO_WINDOW,
                cwd=os.path.dirname(app_path)
            )
        else:
            # Compiled exe next to tray exe
            app_exe = os.path.join(os.path.dirname(sys.executable), "AegisEDR.exe")
            if not os.path.isfile(app_exe):
                app_exe = r"C:\Program Files\AegisEDR\AegisEDR.exe"
            if os.path.isfile(app_exe):
                subprocess.Popen([app_exe],
                                 creationflags=subprocess.CREATE_NO_WINDOW)
    threading.Thread(target=_launch, daemon=True).start()

def open_console(icon, it):
    if _console_url:
        webbrowser.open(_console_url)

def view_logs(icon, it):
    if os.path.exists(LOG_PATH):
        os.startfile(LOG_PATH)
    else:
        os.startfile(r"C:\ProgramData\AegisEDR")

def restart_agent(icon, it):
    subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

def quit_tray(icon, it):
    icon.stop()

# ── Admin actions ─────────────────────────────────────────────────────────────
def _run_ps(cmd: str):
    subprocess.run(
        ["powershell", "-NonInteractive", "-Command", cmd],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
    )

def disable_protection(icon, it):
    global _protection_enabled
    if not IS_ADMIN:
        return
    _run_ps("Set-MpPreference -DisableRealtimeMonitoring $true "
            "-DisableIOAVProtection $true -DisableBehaviorMonitoring $true "
            "-ErrorAction SilentlyContinue")
    subprocess.run(["schtasks", "/End", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    _protection_enabled = False
    icon.icon  = get_icon_image()
    icon.title = "AegisEDR — Protection DISABLED"

def enable_protection(icon, it):
    global _protection_enabled
    if not IS_ADMIN:
        return
    _run_ps("Set-MpPreference -DisableRealtimeMonitoring $false "
            "-DisableIOAVProtection $false -DisableBehaviorMonitoring $false "
            "-ErrorAction SilentlyContinue")
    subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    _protection_enabled = True
    icon.icon  = get_icon_image()
    icon.title = "AegisEDR — Protected ✓"

def scan_file(icon, it):
    """Open file dialog, run YARA scan, show result."""
    if not IS_ADMIN:
        return

    def _run():
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        file_path = filedialog.askopenfilename(
            title="AegisEDR — Select file to scan",
            filetypes=[("All files", "*.*"), ("Executables", "*.exe *.dll *.bat *.ps1")]
        )
        root.destroy()
        if not file_path:
            return

        yara_exe = next((p for p in YARA_EXE_CANDIDATES if os.path.isfile(p)), None)
        rules_file = r"C:\ProgramData\AegisEDR\rules.yar"

        threats = []

        # YARA scan
        if yara_exe and os.path.isfile(rules_file):
            try:
                result = subprocess.run(
                    [yara_exe, rules_file, file_path],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.splitlines():
                    parts = line.strip().split()
                    if parts:
                        threats.append(f"YARA: {parts[0]}")
            except Exception as e:
                threats.append(f"YARA error: {e}")

        # Hash IoC check via console
        cfg = load_config()
        console = cfg.get("console_url", "")
        token = cfg.get("token", "")
        if console and token:
            try:
                import hashlib
                h = hashlib.sha256()
                with open(file_path, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                file_hash = h.hexdigest()
                resp = requests.post(
                    f"{console}/api/ioc/check",
                    json={"value": file_hash, "type": "hash"},
                    headers={"X-Agent-Token": token},
                    verify=False, timeout=5
                )
                if resp.json().get("found"):
                    name = resp.json().get("threat", {}).get("threat_name", "Known Malware")
                    threats.append(f"IoC: {name}")
            except Exception:
                pass

        root2 = tk.Tk()
        root2.withdraw()
        root2.attributes("-topmost", True)
        fname = os.path.basename(file_path)
        if threats:
            messagebox.showwarning(
                "AegisEDR — Threats Found",
                f"File: {fname}\n\nThreats detected:\n" + "\n".join(f"  • {t}" for t in threats)
            )
        else:
            messagebox.showinfo(
                "AegisEDR — Clean",
                f"File: {fname}\n\nNo threats detected."
            )
        root2.destroy()

    threading.Thread(target=_run, daemon=True).start()

# ── Status loop ───────────────────────────────────────────────────────────────
def status_loop(icon: pystray.Icon):
    global _current_status, _threat_count
    import time
    while True:
        try:
            status, threats = get_status()
            _current_status = status
            _threat_count   = threats
            tooltips = {
                "protected":    "AegisEDR — Protected ✓",
                "pending":      "AegisEDR — Waiting for adoption",
                "disconnected": "AegisEDR — Console unreachable",
                "threat":       f"AegisEDR — {threats} active threat(s)!",
                "disabled":     "AegisEDR — Protection DISABLED",
            }
            icon.icon  = get_icon_image()
            icon.title = tooltips.get(status, "AegisEDR Agent")
        except Exception:
            pass
        time.sleep(30)

# ── Build menu ────────────────────────────────────────────────────────────────
def build_menu() -> pystray.Menu:
    admin_label = " [Admin]" if IS_ADMIN else " [Admin only]"

    base_items = [
        item("AegisEDR Agent v1.0.0", lambda i, it: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item("Open Dashboard", open_app, default=True),
        item("Open Web Console", open_console),
        item("View Logs",    view_logs),
        pystray.Menu.SEPARATOR,
    ]

    admin_items = [
        item(f"Disable Protection{admin_label}", disable_protection, enabled=IS_ADMIN),
        item(f"Enable Protection{admin_label}",  enable_protection,  enabled=IS_ADMIN),
        item(f"Scan File...{admin_label}",        scan_file,          enabled=IS_ADMIN),
        pystray.Menu.SEPARATOR,
    ]

    footer_items = [
        item("Restart Agent", restart_agent),
        pystray.Menu.SEPARATOR,
        item("Quit Tray", quit_tray),
    ]

    return pystray.Menu(*base_items, *admin_items, *footer_items)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    icon_img = get_icon_image()
    icon = pystray.Icon(
        "AegisEDR",
        icon_img,
        "AegisEDR Agent",
        build_menu()
    )
    threading.Thread(target=status_loop, args=(icon,), daemon=True).start()
    icon.run()

if __name__ == "__main__":
    main()
