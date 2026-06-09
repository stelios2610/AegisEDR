"""
AegisEDR Standalone Tray Icon
Reads status from local SQLite — no server required.
Build: pyinstaller --onefile --noconsole --name AegisEDR-Tray tray_standalone.py
"""
import os
import sys
import sqlite3
import threading
import subprocess
import ctypes
import time
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
except ImportError:
    os.system(f"{sys.executable} -m pip install pystray Pillow")
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw

DATA_DIR       = r"C:\ProgramData\AegisEDR"
DB_PATH        = os.path.join(DATA_DIR, "aegisedr.db")
LOG_PATH       = os.path.join(DATA_DIR, "agent.log")
QUARANTINE_DIR = os.path.join(DATA_DIR, "Quarantine")

# ── Admin check ───────────────────────────────────────────────────────────────
def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

IS_ADMIN = _is_admin()

# ── Status colors ─────────────────────────────────────────────────────────────
STATUS_COLORS = {
    "protected":  (99,  102, 241),
    "threat":     (239,  68,  68),
    "starting":   (234, 179,   8),
    "stopped":    (100, 100, 100),
    "offline":    (148, 163, 184),
    "disabled":   (100, 100, 100),
}

_current_status     = "offline"
_threat_count       = 0
_protection_enabled = True

# ── DB helpers ────────────────────────────────────────────────────────────────
def _get_db() -> sqlite3.Connection | None:
    if not os.path.isfile(DB_PATH):
        return None
    try:
        c = sqlite3.connect(DB_PATH, timeout=3)
        c.row_factory = sqlite3.Row
        return c
    except Exception:
        return None

def get_status() -> tuple[str, int]:
    global _protection_enabled
    if not _protection_enabled:
        return "disabled", 0
    conn = _get_db()
    if not conn:
        return "offline", 0
    try:
        with conn:
            prot = conn.execute("SELECT value FROM settings WHERE key='protection_status'").fetchone()
            if not prot:
                return "offline", 0
            prot_val = prot["value"]
            threats = conn.execute(
                "SELECT COUNT(*) as n FROM threats WHERE status='active'"
            ).fetchone()["n"]

            if prot_val in ("active", "limited") and threats == 0:
                return "protected", 0
            elif threats > 0:
                return "threat", threats
            elif prot_val == "stopped":
                return "stopped", 0
            elif prot_val == "starting":
                return "starting", 0
            else:
                return "offline", 0
    except Exception:
        return "offline", 0

# ── Icon generation ───────────────────────────────────────────────────────────
def make_icon(color: tuple, badge: int = 0, disabled: bool = False) -> Image.Image:
    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = size // 2, size // 2

    shield = [
        (cx,      4),
        (cx+26,  14), (cx+26,  34),
        (cx+18,  50), (cx,     60),
        (cx-18,  50), (cx-26,  34),
        (cx-26,  14),
    ]
    draw.polygon(shield, fill=color + (255,))
    inner = [(x*0.82+cx*0.18, y*0.82+cy*0.18) for x, y in shield]
    draw.polygon(inner, fill=(255, 255, 255, 30))

    if disabled:
        draw.line([(cx-12, cy-12), (cx+12, cy+12)], fill=(220, 50, 50, 255), width=5)
        draw.line([(cx+12, cy-12), (cx-12, cy+12)], fill=(220, 50, 50, 255), width=5)
    else:
        draw.text((cx-9, cy-16), "A", fill=(255, 255, 255, 240))

    if badge > 0:
        draw.ellipse([44, 44, 60, 60], fill=(239, 68, 68, 255))
        label = str(badge) if badge < 10 else "!"
        draw.text((48 if badge < 10 else 47, 46), label, fill=(255, 255, 255, 255))

    return img

def get_icon_image() -> Image.Image:
    color    = STATUS_COLORS.get(_current_status, STATUS_COLORS["offline"])
    disabled = (_current_status == "disabled")
    return make_icon(color, _threat_count if _current_status == "threat" else 0, disabled)

# ── Menu actions ──────────────────────────────────────────────────────────────
def open_app(icon=None, it=None):
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "AegisEDR.exe"),
        r"C:\Program Files\AegisEDR\AegisEDR.exe",
        r"C:\Program Files (x86)\AegisEDR\AegisEDR.exe",
    ]
    app_exe = next((p for p in candidates if os.path.isfile(p)), None)
    if app_exe:
        subprocess.Popen([app_exe], creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        os.startfile(DATA_DIR)

def quick_scan(icon=None, it=None):
    try:
        conn = _get_db()
        if conn:
            with conn:
                conn.execute(
                    "INSERT INTO scan_queue (scan_type, status) VALUES ('quick','pending')"
                )
    except Exception:
        pass

def view_logs(icon, it):
    if os.path.isfile(LOG_PATH):
        os.startfile(LOG_PATH)
    else:
        os.startfile(DATA_DIR)

def restart_agent(icon, it):
    subprocess.run(["schtasks", "/End", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    time.sleep(1)
    subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

def quit_tray(icon, it):
    icon.stop()

# ── Admin actions ─────────────────────────────────────────────────────────────
def _run_ps(cmd: str):
    subprocess.run(["powershell", "-NonInteractive", "-Command", cmd],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

def disable_protection(icon, it):
    global _protection_enabled
    if not IS_ADMIN:
        return
    try:
        conn = _get_db()
        if conn:
            with conn:
                conn.execute("INSERT OR REPLACE INTO settings VALUES ('realtime_enabled','0')")
    except Exception:
        pass
    _protection_enabled = False
    icon.icon  = get_icon_image()
    icon.title = "AegisEDR — Protection DISABLED"

def enable_protection(icon, it):
    global _protection_enabled
    if not IS_ADMIN:
        return
    try:
        conn = _get_db()
        if conn:
            with conn:
                conn.execute("INSERT OR REPLACE INTO settings VALUES ('realtime_enabled','1')")
    except Exception:
        pass
    subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                   capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    _protection_enabled = True
    icon.icon  = get_icon_image()
    icon.title = "AegisEDR — Protected"

def scan_file_menu(icon, it):
    if not IS_ADMIN:
        return

    def _run():
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askopenfilename(
            title="AegisEDR — Select file to scan",
            filetypes=[("All files", "*.*"), ("Executables", "*.exe *.dll *.bat *.ps1")]
        )
        root.destroy()
        if not path:
            return

        # Queue the scan via DB
        try:
            conn = _get_db()
            if conn:
                with conn:
                    conn.execute(
                        "INSERT INTO scan_queue (scan_type, scan_path, status) VALUES ('custom',?,'pending')",
                        (os.path.dirname(path),)
                    )
        except Exception:
            pass

        root2 = tk.Tk()
        root2.withdraw()
        root2.attributes("-topmost", True)
        messagebox.showinfo("AegisEDR", f"Scan queued for:\n{path}\n\nCheck the AegisEDR app for results.")
        root2.destroy()

    threading.Thread(target=_run, daemon=True).start()

# ── Status loop ───────────────────────────────────────────────────────────────
def status_loop(icon: pystray.Icon):
    global _current_status, _threat_count
    while True:
        try:
            status, threats = get_status()
            _current_status = status
            _threat_count   = threats
            tooltips = {
                "protected": "AegisEDR — Protected",
                "threat":    f"AegisEDR — {threats} active threat(s)!",
                "starting":  "AegisEDR — Starting...",
                "stopped":   "AegisEDR — Stopped",
                "offline":   "AegisEDR — Agent Offline",
                "disabled":  "AegisEDR — Protection DISABLED",
            }
            icon.icon  = get_icon_image()
            icon.title = tooltips.get(status, "AegisEDR")
        except Exception:
            pass
        time.sleep(20)

# ── Menu ──────────────────────────────────────────────────────────────────────
def build_menu() -> pystray.Menu:
    admin_sfx = " [Admin]" if IS_ADMIN else " [Admin only]"
    return pystray.Menu(
        item("AegisEDR Standalone v2.0", lambda i,it: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item("Open Dashboard", open_app, default=True),
        item("Quick Scan", quick_scan),
        item("View Logs", view_logs),
        pystray.Menu.SEPARATOR,
        item(f"Disable Protection{admin_sfx}", disable_protection, enabled=IS_ADMIN),
        item(f"Enable Protection{admin_sfx}",  enable_protection,  enabled=IS_ADMIN),
        item(f"Scan File...{admin_sfx}",        scan_file_menu,     enabled=IS_ADMIN),
        pystray.Menu.SEPARATOR,
        item("Restart Agent", restart_agent),
        pystray.Menu.SEPARATOR,
        item("Quit Tray", quit_tray),
    )

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    icon_img = get_icon_image()
    icon = pystray.Icon("AegisEDR", icon_img, "AegisEDR", build_menu())
    threading.Thread(target=status_loop, args=(icon,), daemon=True).start()
    icon.run()

if __name__ == "__main__":
    main()
