"""
AegisEDR Windows Console Application
Native Windows GUI - replaces browser console for endpoint view.
Build: pyinstaller --onefile --noconsole --name AegisEDR --icon ../assets/icon.ico app_windows.py
"""
import os
import sys
import json
import ctypes
import threading
import subprocess
import time
from datetime import datetime
from pathlib import Path

try:
    import customtkinter as ctk
    from PIL import Image, ImageDraw
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "customtkinter", "pillow"],
                   capture_output=True)
    import customtkinter as ctk
    from PIL import Image, ImageDraw

try:
    import requests
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "requests"], capture_output=True)
    import requests

CONFIG_PATH   = r"C:\ProgramData\AegisEDR\config.json"
LOG_PATH      = r"C:\ProgramData\AegisEDR\agent.log"
QUARANTINE_DIR = r"C:\ProgramData\AegisEDR\Quarantine"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Helpers ───────────────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

IS_ADMIN = is_admin()

# ── Shield image ──────────────────────────────────────────────────────────────
def make_shield(size: int, color: tuple, disabled=False) -> ctk.CTkImage:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = size // 2, size // 2
    s = size
    shield = [
        (cx,       int(s*0.06)),
        (cx+int(s*0.4), int(s*0.20)),
        (cx+int(s*0.4), int(s*0.52)),
        (cx+int(s*0.28),int(s*0.76)),
        (cx,       int(s*0.94)),
        (cx-int(s*0.28),int(s*0.76)),
        (cx-int(s*0.4), int(s*0.52)),
        (cx-int(s*0.4), int(s*0.20)),
    ]
    draw.polygon(shield, fill=color + (255,))
    inner = [(x*0.80+cx*0.20, y*0.80+cy*0.20) for x,y in shield]
    draw.polygon(inner, fill=(255,255,255,25))
    if disabled:
        lw = max(4, size//16)
        draw.line([(cx-size//5, cy-size//5), (cx+size//5, cy+size//5)], fill=(220,50,50,255), width=lw)
        draw.line([(cx+size//5, cy-size//5), (cx-size//5, cy+size//5)], fill=(220,50,50,255), width=lw)
    else:
        # Checkmark
        lw = max(3, size//20)
        draw.line([(cx-size//8, cy), (cx-size//24, cy+size//8), (cx+size//8, cy-size//10)],
                  fill=(255,255,255,230), width=lw)
    return ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))


# ── API helpers ───────────────────────────────────────────────────────────────
class API:
    def __init__(self):
        cfg = load_config()
        self.url   = cfg.get("console_url", "").rstrip("/")
        self.token = cfg.get("token", "")
        self.endpoint_id = cfg.get("endpoint_id")

    def _h(self):
        return {"X-Agent-Token": self.token}

    def get_threats(self) -> list:
        try:
            r = requests.get(f"{self.url}/api/threats", headers=self._h(), verify=False, timeout=5)
            return r.json().get("threats", []) if r.ok else []
        except Exception:
            return []

    def get_stats(self) -> dict:
        try:
            r = requests.get(f"{self.url}/api/stats", headers=self._h(), verify=False, timeout=5)
            return r.json() if r.ok else {}
        except Exception:
            return {}

    def get_endpoint_status(self) -> dict:
        if not self.endpoint_id:
            return {}
        try:
            r = requests.get(f"{self.url}/api/endpoints/{self.endpoint_id}/status",
                             headers=self._h(), verify=False, timeout=5)
            return r.json() if r.ok else {}
        except Exception:
            return {}

    def connected(self) -> bool:
        try:
            r = requests.get(f"{self.url}/api/stats", headers=self._h(), verify=False, timeout=3)
            return r.status_code < 500
        except Exception:
            return False


# ── Main Application ──────────────────────────────────────────────────────────
class AegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AegisEDR Security")
        self.geometry("920x620")
        self.minsize(800, 560)
        self.resizable(True, True)

        # Try to set icon
        try:
            ico = os.path.join(os.path.dirname(__file__), "..", "assets", "icon.ico")
            if os.path.exists(ico):
                self.iconbitmap(ico)
        except Exception:
            pass

        self.api = API()
        self._status = "checking"
        self._threats = []
        self._scan_running = False

        self._build_ui()
        self._refresh()
        self._start_auto_refresh()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)

        # Logo
        logo = ctk.CTkLabel(self.sidebar, text="  AegisEDR",
                             font=ctk.CTkFont(size=20, weight="bold"),
                             text_color="#6366f1")
        logo.grid(row=0, column=0, padx=20, pady=(24, 4), sticky="w")
        ver = ctk.CTkLabel(self.sidebar, text="  Endpoint Security v1.0",
                           font=ctk.CTkFont(size=11), text_color="gray")
        ver.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")

        # Nav buttons
        self._nav_btns = {}
        nav_items = [
            ("Dashboard",   "dashboard"),
            ("Threats",     "threats"),
            ("Scan",        "scan"),
            ("Quarantine",  "quarantine"),
            ("Logs",        "logs"),
        ]
        if IS_ADMIN:
            nav_items.append(("Settings", "settings"))

        for i, (label, key) in enumerate(nav_items):
            btn = ctk.CTkButton(
                self.sidebar, text=label, anchor="w",
                font=ctk.CTkFont(size=14),
                fg_color="transparent", hover_color="#374151",
                command=lambda k=key: self._show_page(k)
            )
            btn.grid(row=i+2, column=0, padx=10, pady=2, sticky="ew")
            self._nav_btns[key] = btn

        # Status indicator at bottom of sidebar
        self.sidebar_status = ctk.CTkLabel(self.sidebar, text="● Connecting...",
                                            font=ctk.CTkFont(size=12), text_color="gray")
        self.sidebar_status.grid(row=9, column=0, padx=20, pady=20, sticky="w")

        # Main content area
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self._pages = {}
        self._build_dashboard()
        self._build_threats()
        self._build_scan()
        self._build_quarantine()
        self._build_logs()
        if IS_ADMIN:
            self._build_settings()

        self._show_page("dashboard")

    def _show_page(self, key):
        for k, frame in self._pages.items():
            frame.grid_remove()
        self._pages[key].grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        for k, btn in self._nav_btns.items():
            btn.configure(fg_color="#374151" if k == key else "transparent")

    # ── Dashboard ─────────────────────────────────────────────────────────────
    def _build_dashboard(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        self._pages["dashboard"] = f

        # Header
        ctk.CTkLabel(f, text="Security Dashboard",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 20))

        # Status card
        self.status_card = ctk.CTkFrame(f, corner_radius=16, height=220)
        self.status_card.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        self.status_card.grid_columnconfigure(1, weight=1)
        self.status_card.grid_propagate(False)

        self.shield_lbl = ctk.CTkLabel(self.status_card, text="")
        self.shield_lbl.grid(row=0, column=0, rowspan=3, padx=30, pady=20)

        self.status_title = ctk.CTkLabel(self.status_card, text="Checking...",
                                          font=ctk.CTkFont(size=26, weight="bold"))
        self.status_title.grid(row=0, column=1, sticky="sw", pady=(30, 0))

        self.status_sub = ctk.CTkLabel(self.status_card, text="Connecting to agent...",
                                        font=ctk.CTkFont(size=14), text_color="gray")
        self.status_sub.grid(row=1, column=1, sticky="nw", pady=(4, 0))

        self.status_time = ctk.CTkLabel(self.status_card, text="",
                                         font=ctk.CTkFont(size=12), text_color="gray")
        self.status_time.grid(row=2, column=1, sticky="nw")

        # Stats row
        stats_frame = ctk.CTkFrame(f, fg_color="transparent")
        stats_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        stats_frame.grid_columnconfigure((0,1,2,3), weight=1)

        self._stat_cards = {}
        for i, (key, label, color) in enumerate([
            ("threats_today", "Threats Today",   "#ef4444"),
            ("total_threats", "Total Threats",    "#f97316"),
            ("files_scanned", "Files Scanned",    "#6366f1"),
            ("last_scan",     "Last Scan",        "#10b981"),
        ]):
            card = ctk.CTkFrame(stats_frame, corner_radius=12)
            card.grid(row=0, column=i, padx=6, sticky="ew")
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=12),
                         text_color="gray").grid(row=0, column=0, padx=16, pady=(14,0), sticky="w")
            val_lbl = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=22, weight="bold"),
                                    text_color=color)
            val_lbl.grid(row=1, column=0, padx=16, pady=(2,14), sticky="w")
            self._stat_cards[key] = val_lbl

        # Quick actions
        act_frame = ctk.CTkFrame(f, fg_color="transparent")
        act_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        act_frame.grid_columnconfigure((0,1), weight=1)

        ctk.CTkButton(act_frame, text="Quick Scan", height=44,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=lambda: self._start_scan("quick")).grid(
            row=0, column=0, padx=(0,8), sticky="ew")
        ctk.CTkButton(act_frame, text="Full Scan", height=44,
                      font=ctk.CTkFont(size=14), fg_color="#374151", hover_color="#4b5563",
                      command=lambda: self._start_scan("full")).grid(
            row=0, column=1, padx=(8,0), sticky="ew")

    # ── Threats ───────────────────────────────────────────────────────────────
    def _build_threats(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(1, weight=1)
        self._pages["threats"] = f

        ctk.CTkLabel(f, text="Detected Threats",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 16))

        self.threats_scroll = ctk.CTkScrollableFrame(f, corner_radius=12)
        self.threats_scroll.grid(row=1, column=0, sticky="nsew")
        self.threats_scroll.grid_columnconfigure(0, weight=1)
        self._threat_rows = []

    def _refresh_threats_ui(self):
        for w in self._threat_rows:
            w.destroy()
        self._threat_rows = []

        threats = self._threats
        if not threats:
            lbl = ctk.CTkLabel(self.threats_scroll,
                               text="No threats detected  ✓",
                               font=ctk.CTkFont(size=15), text_color="#10b981")
            lbl.grid(row=0, column=0, pady=40)
            self._threat_rows.append(lbl)
            return

        SEV_COLOR = {"critical": "#ef4444", "high": "#f97316",
                     "medium": "#eab308", "low": "#6366f1"}

        for i, t in enumerate(threats):
            row = ctk.CTkFrame(self.threats_scroll, corner_radius=10, height=72)
            row.grid(row=i, column=0, sticky="ew", pady=4)
            row.grid_columnconfigure(1, weight=1)
            row.grid_propagate(False)

            sev = t.get("severity", "low")
            color = SEV_COLOR.get(sev, "#6366f1")

            # Severity bar
            bar = ctk.CTkFrame(row, width=6, corner_radius=3, fg_color=color)
            bar.grid(row=0, column=0, rowspan=2, padx=(10,12), pady=10, sticky="ns")

            ctk.CTkLabel(row, text=t.get("name", "Unknown Threat"),
                         font=ctk.CTkFont(size=13, weight="bold"),
                         anchor="w").grid(row=0, column=1, sticky="sw", pady=(12,0))

            detail = f"{t.get('threat_type','').upper()}  ·  {t.get('file_path','')[:60]}"
            ctk.CTkLabel(row, text=detail, font=ctk.CTkFont(size=11),
                         text_color="gray", anchor="w").grid(row=1, column=1, sticky="nw")

            sev_tag = ctk.CTkLabel(row, text=sev.upper(),
                                    font=ctk.CTkFont(size=11, weight="bold"),
                                    text_color=color)
            sev_tag.grid(row=0, column=2, padx=16, pady=(12,0), sticky="e")

            ts = t.get("detected_at", "")[:16]
            ctk.CTkLabel(row, text=ts, font=ctk.CTkFont(size=11),
                         text_color="gray").grid(row=1, column=2, padx=16, sticky="e")

            self._threat_rows.append(row)

    # ── Scan ──────────────────────────────────────────────────────────────────
    def _build_scan(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        self._pages["scan"] = f

        ctk.CTkLabel(f, text="Scan",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 20))

        # Scan type buttons
        types_frame = ctk.CTkFrame(f, fg_color="transparent")
        types_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        types_frame.grid_columnconfigure((0,1,2), weight=1)

        for i, (label, stype, desc) in enumerate([
            ("Quick Scan",  "quick",  "Scans common locations\n~2 minutes"),
            ("Full Scan",   "full",   "Scans entire system\n~20+ minutes"),
            ("Custom Scan", "custom", "Choose a specific folder"),
        ]):
            card = ctk.CTkFrame(types_frame, corner_radius=12, height=120)
            card.grid(row=0, column=i, padx=6, sticky="ew")
            card.grid_propagate(False)
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=label,
                         font=ctk.CTkFont(size=14, weight="bold")).grid(
                row=0, column=0, padx=16, pady=(20,4), sticky="w")
            ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(size=11),
                         text_color="gray").grid(row=1, column=0, padx=16, sticky="w")
            ctk.CTkButton(card, text="Start", height=30,
                          command=lambda s=stype: self._start_scan(s)).grid(
                row=2, column=0, padx=16, pady=(8,16), sticky="w")

        # Progress area
        prog_card = ctk.CTkFrame(f, corner_radius=12)
        prog_card.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        prog_card.grid_columnconfigure(0, weight=1)

        self.scan_status_lbl = ctk.CTkLabel(prog_card, text="No scan running",
                                             font=ctk.CTkFont(size=14))
        self.scan_status_lbl.grid(row=0, column=0, padx=20, pady=(16,8), sticky="w")

        self.scan_progress = ctk.CTkProgressBar(prog_card, height=12)
        self.scan_progress.grid(row=1, column=0, padx=20, pady=(0,8), sticky="ew")
        self.scan_progress.set(0)

        self.scan_file_lbl = ctk.CTkLabel(prog_card, text="",
                                           font=ctk.CTkFont(size=11), text_color="gray")
        self.scan_file_lbl.grid(row=2, column=0, padx=20, pady=(0,16), sticky="w")

    def _start_scan(self, scan_type: str):
        if self._scan_running:
            return
        if scan_type == "custom":
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
            folder = filedialog.askdirectory(title="Select folder to scan")
            root.destroy()
            if not folder:
                return
        else:
            folder = ""

        self._show_page("scan")
        self._scan_running = True
        self.scan_progress.set(0)
        self.scan_status_lbl.configure(text=f"Starting {scan_type} scan...")

        threading.Thread(target=self._run_scan, args=(scan_type, folder), daemon=True).start()

    def _run_scan(self, scan_type: str, folder: str):
        import hashlib, math

        yara_candidates = [
            os.path.join(getattr(sys, "_MEIPASS", ""), "yara64.exe"),
            r"C:\Program Files\AegisEDR Agent\yara64.exe",
            os.path.join(os.path.dirname(__file__), "yara_bin", "yara64.exe"),
        ]
        yara_exe   = next((p for p in yara_candidates if os.path.isfile(p)), None)
        rules_file = r"C:\ProgramData\AegisEDR\rules.yar"

        scan_dirs = {
            "quick":  [os.path.expanduser("~"), r"C:\Windows\Temp", r"C:\Temp"],
            "full":   [r"C:\Users", r"C:\Windows\Temp", r"C:\ProgramData"],
            "custom": [folder],
        }.get(scan_type, [folder or os.path.expanduser("~")])

        SCAN_EXT = {".exe",".dll",".bat",".ps1",".vbs",".js",".hta",".msi",".scr"}
        files_found, files_done, threats = 0, 0, 0

        # Count files first
        all_files = []
        for d in [x for x in scan_dirs if os.path.isdir(x)]:
            for root, _, fnames in os.walk(d):
                for fn in fnames:
                    if Path(fn).suffix.lower() in SCAN_EXT:
                        all_files.append(os.path.join(root, fn))

        total = len(all_files) or 1
        self.after(0, lambda: self.scan_status_lbl.configure(
            text=f"Scanning {total} files..."))

        for fp in all_files:
            files_done += 1
            prog = files_done / total
            lbl = os.path.basename(fp)
            self.after(0, lambda p=prog, l=lbl: (
                self.scan_progress.set(p),
                self.scan_file_lbl.configure(text=f"Scanning: {l}")
            ))

            try:
                if not os.path.isfile(fp) or os.path.getsize(fp) > 50*1024*1024:
                    continue
                if yara_exe and os.path.isfile(rules_file):
                    res = subprocess.run([yara_exe, rules_file, fp],
                                         capture_output=True, text=True, timeout=10)
                    if res.stdout.strip():
                        threats += 1
            except Exception:
                pass

        self._scan_running = False
        msg = f"Scan complete — {files_done} files scanned, {threats} threat(s) found"
        self.after(0, lambda: (
            self.scan_status_lbl.configure(text=msg),
            self.scan_file_lbl.configure(text=""),
            self.scan_progress.set(1.0),
            self._refresh()
        ))

    # ── Quarantine ────────────────────────────────────────────────────────────
    def _build_quarantine(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(1, weight=1)
        self._pages["quarantine"] = f

        ctk.CTkLabel(f, text="Quarantine",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 16))

        self.quar_scroll = ctk.CTkScrollableFrame(f, corner_radius=12)
        self.quar_scroll.grid(row=1, column=0, sticky="nsew")
        self.quar_scroll.grid_columnconfigure(0, weight=1)
        self._refresh_quarantine()

    def _refresh_quarantine(self):
        for w in self.quar_scroll.winfo_children():
            w.destroy()
        files = []
        if os.path.isdir(QUARANTINE_DIR):
            files = [f for f in os.listdir(QUARANTINE_DIR) if f.endswith(".quar")]
        if not files:
            ctk.CTkLabel(self.quar_scroll, text="Quarantine is empty  ✓",
                         font=ctk.CTkFont(size=15), text_color="#10b981").grid(
                row=0, column=0, pady=40)
            return
        for i, fname in enumerate(files):
            row = ctk.CTkFrame(self.quar_scroll, corner_radius=10)
            row.grid(row=i, column=0, sticky="ew", pady=4)
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row, text=fname, font=ctk.CTkFont(size=12),
                         anchor="w").grid(row=0, column=0, padx=16, pady=12, sticky="w")

    # ── Logs ──────────────────────────────────────────────────────────────────
    def _build_logs(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(1, weight=1)
        self._pages["logs"] = f

        hdr = ctk.CTkFrame(f, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="Agent Logs",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(hdr, text="Refresh", width=90,
                      command=self._refresh_logs).grid(row=0, column=1, sticky="e")

        self.log_box = ctk.CTkTextbox(f, corner_radius=12, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.grid(row=1, column=0, sticky="nsew")
        self._refresh_logs()

    def _refresh_logs(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        try:
            with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            self.log_box.insert("end", "".join(lines[-200:]))
            self.log_box.see("end")
        except Exception:
            self.log_box.insert("end", "Log file not found.")
        self.log_box.configure(state="disabled")

    # ── Settings (admin only) ─────────────────────────────────────────────────
    def _build_settings(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        self._pages["settings"] = f

        ctk.CTkLabel(f, text="Settings  [Admin]",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 20))

        # Protection toggle card
        prot_card = ctk.CTkFrame(f, corner_radius=12)
        prot_card.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        prot_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(prot_card, text="Real-time Protection",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(16, 4), sticky="w")
        ctk.CTkLabel(prot_card, text="Enable or disable AegisEDR real-time file monitoring.",
                     font=ctk.CTkFont(size=12), text_color="gray").grid(
            row=1, column=0, padx=20, pady=(0, 12), sticky="w")

        btn_frame = ctk.CTkFrame(prot_card, fg_color="transparent")
        btn_frame.grid(row=2, column=0, padx=20, pady=(0, 16), sticky="w")
        ctk.CTkButton(btn_frame, text="Enable Protection", width=160,
                      fg_color="#10b981", hover_color="#059669",
                      command=self._enable_protection).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(btn_frame, text="Disable Protection", width=160,
                      fg_color="#ef4444", hover_color="#dc2626",
                      command=self._disable_protection).grid(row=0, column=1)

        # Agent service card
        svc_card = ctk.CTkFrame(f, corner_radius=12)
        svc_card.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        svc_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(svc_card, text="Agent Service",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(16, 4), sticky="w")
        svc_btns = ctk.CTkFrame(svc_card, fg_color="transparent")
        svc_btns.grid(row=1, column=0, padx=20, pady=(0, 16), sticky="w")
        ctk.CTkButton(svc_btns, text="Restart Agent", width=140,
                      command=self._restart_agent).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(svc_btns, text="Stop Agent", width=140,
                      fg_color="#374151", hover_color="#4b5563",
                      command=self._stop_agent).grid(row=0, column=1)

    def _enable_protection(self):
        subprocess.run(["powershell", "-NonInteractive", "-Command",
                        "Set-MpPreference -DisableRealtimeMonitoring $false "
                        "-ErrorAction SilentlyContinue"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def _disable_protection(self):
        subprocess.run(["powershell", "-NonInteractive", "-Command",
                        "Set-MpPreference -DisableRealtimeMonitoring $true "
                        "-ErrorAction SilentlyContinue"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["schtasks", "/End", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def _restart_agent(self):
        subprocess.run(["schtasks", "/End", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(1)
        subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def _stop_agent(self):
        subprocess.run(["schtasks", "/End", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    # ── Refresh logic ─────────────────────────────────────────────────────────
    def _refresh(self):
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _do_refresh(self):
        connected = self.api.connected()
        if not connected:
            self.after(0, self._set_status_disconnected)
            return

        stats  = self.api.get_stats()
        ep     = self.api.get_endpoint_status()
        threats = self.api.get_threats()
        self._threats = threats

        self.after(0, lambda: self._update_ui(stats, ep, threats))

    def _set_status_disconnected(self):
        shield = make_shield(96, (100, 100, 100))
        self.shield_lbl.configure(image=shield)
        self.status_title.configure(text="Disconnected", text_color="#9ca3af")
        self.status_sub.configure(text="Cannot reach AegisEDR agent service")
        self.sidebar_status.configure(text="● Disconnected", text_color="#9ca3af")

    def _update_ui(self, stats, ep, threats):
        sev = stats.get("threats_by_severity", {})
        total_threats = sum(sev.values())
        approved = ep.get("approved", False)

        if not approved:
            status, color, title, sub = "pending", (234,179,8), "Pending Approval", \
                "Waiting for admin to approve this endpoint in the console."
        elif total_threats > 0:
            status, color, title, sub = "threat", (239,68,68), \
                f"{total_threats} Threat(s) Detected!", "Immediate action required."
        else:
            status, color, title, sub = "protected", (16,185,129), \
                "You're Protected", "All systems are secure."

        shield = make_shield(96, color, disabled=(status=="pending"))
        self.shield_lbl.configure(image=shield)
        self.status_title.configure(
            text=title,
            text_color=f"#{color[0]:02x}{color[1]:02x}{color[2]:02x}")
        self.status_sub.configure(text=sub)
        self.status_time.configure(
            text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

        sidebar_colors = {"protected":"#10b981","threat":"#ef4444",
                          "pending":"#eab308","disconnected":"#9ca3af"}
        self.sidebar_status.configure(
            text=f"● {title}",
            text_color=sidebar_colors.get(status, "gray"))

        self._stat_cards["threats_today"].configure(text=str(sev.get("critical",0)+sev.get("high",0)))
        self._stat_cards["total_threats"].configure(text=str(total_threats))
        self._stat_cards["files_scanned"].configure(text=str(stats.get("files_scanned", "—")))
        self._stat_cards["last_scan"].configure(text=str(stats.get("last_scan", "Never"))[:10])

        self._refresh_threats_ui()

    def _start_auto_refresh(self):
        def loop():
            while True:
                time.sleep(30)
                self._refresh()
        threading.Thread(target=loop, daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    app = AegisApp()
    app.mainloop()

if __name__ == "__main__":
    main()
