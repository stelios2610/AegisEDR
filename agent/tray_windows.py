"""
AegisEDR Windows System Tray Monitor
Shows agent status in system tray with right-click menu.
Build: pyinstaller --onefile --noconsole --name AegisEDR-Tray --icon ../assets/icon.ico tray_windows.py
"""
import os
import sys
import json
import threading
import subprocess
import webbrowser
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

# ── Status ────────────────────────────────────────────────────────────────────
STATUS_COLORS = {
    "protected":   (99,  102, 241),   # indigo
    "pending":     (234, 179,   8),   # yellow
    "disconnected":(148, 163, 184),   # gray
    "threat":      (239,  68,  68),   # red
}

_current_status = "disconnected"
_threat_count   = 0
_console_url    = ""

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
            threats = data.get("threats_by_severity", {})
            total = sum(threats.values())
            if total > 0:
                return "threat", total
            return "protected", 0
        elif resp.status_code == 401:
            return "pending", 0
    except Exception:
        pass
    return "disconnected", 0

# ── Icon generation ───────────────────────────────────────────────────────────
def make_icon(color: tuple, badge: int = 0) -> Image.Image:
    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield shape (polygon approximation)
    cx, cy = size // 2, size // 2
    shield = [
        (cx, 4),
        (cx + 26, 14), (cx + 26, 34),
        (cx + 18, 50), (cx, 60),
        (cx - 18, 50), (cx - 26, 34),
        (cx - 26, 14),
    ]
    draw.polygon(shield, fill=color + (255,))

    # Inner highlight
    inner = [(x * 0.82 + cx * 0.18, y * 0.82 + cy * 0.18) for x, y in shield]
    draw.polygon(inner, fill=(255, 255, 255, 30))

    # "A" letter
    draw.text((cx - 9, cy - 16), "A", fill=(255, 255, 255, 240), font=None)

    # Badge (threat count)
    if badge > 0:
        draw.ellipse([44, 44, 60, 60], fill=(239, 68, 68, 255))
        label = str(badge) if badge < 10 else "!"
        draw.text((48 if badge < 10 else 47, 46), label, fill=(255, 255, 255, 255))

    return img

def get_icon_image() -> Image.Image:
    color = STATUS_COLORS.get(_current_status, STATUS_COLORS["disconnected"])
    return make_icon(color, _threat_count if _current_status == "threat" else 0)

# ── Menu actions ──────────────────────────────────────────────────────────────
def open_console(icon, item):
    if _console_url:
        webbrowser.open(_console_url)

def view_logs(icon, item):
    if os.path.exists(LOG_PATH):
        os.startfile(LOG_PATH)
    else:
        os.startfile(r"C:\ProgramData\AegisEDR")

def restart_agent(icon, item):
    subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

def stop_agent(icon, item):
    subprocess.run(["schtasks", "/End", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

def quit_tray(icon, item):
    icon.stop()

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
            }
            icon.icon   = get_icon_image()
            icon.title  = tooltips.get(status, "AegisEDR Agent")
        except Exception:
            pass
        time.sleep(30)

# ── Build menu ────────────────────────────────────────────────────────────────
def build_menu() -> pystray.Menu:
    return pystray.Menu(
        item("AegisEDR Agent v1.0.0", lambda i, it: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item("Open Console",    open_console),
        item("View Logs",       view_logs),
        pystray.Menu.SEPARATOR,
        item("Restart Agent",   restart_agent),
        item("Stop Agent",      stop_agent),
        pystray.Menu.SEPARATOR,
        item("Quit Tray",       quit_tray),
    )

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
