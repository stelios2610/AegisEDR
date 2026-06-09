"""
AegisEDR Standalone Console Application
Native Windows GUI — reads from local SQLite, no server needed.
Build: pyinstaller --onefile --noconsole --name AegisEDR
       --collect-all=customtkinter app_standalone.py
"""
import os
import sys
import ctypes
import threading
import subprocess
import sqlite3
import time
import tkinter as tk
from tkinter import filedialog
from datetime import datetime

try:
    import customtkinter as ctk
    from PIL import Image, ImageDraw
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "customtkinter", "pillow"],
                   capture_output=True)
    import customtkinter as ctk
    from PIL import Image, ImageDraw

AGENT_VERSION  = "2.0.0"
DATA_DIR       = r"C:\ProgramData\AegisEDR"
DB_PATH        = os.path.join(DATA_DIR, "aegisedr.db")
LOG_PATH       = os.path.join(DATA_DIR, "agent.log")
QUARANTINE_DIR = os.path.join(DATA_DIR, "Quarantine")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Helpers ───────────────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

IS_ADMIN = is_admin()

# ── Local DB layer ────────────────────────────────────────────────────────────
class LocalDB:
    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(DB_PATH, timeout=5)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _setting(self, key: str, default=None):
        try:
            with self._conn() as c:
                row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
                return row["value"] if row else default
        except Exception:
            return default

    def _set_setting(self, key: str, value: str):
        try:
            with self._conn() as c:
                c.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, str(value)))
                c.commit()
        except Exception:
            pass

    def db_exists(self) -> bool:
        return os.path.isfile(DB_PATH)

    def get_stats(self) -> dict:
        if not self.db_exists():
            return {}
        try:
            with self._conn() as c:
                threats = c.execute(
                    "SELECT severity, COUNT(*) as n FROM threats WHERE status='active' GROUP BY severity"
                ).fetchall()
                sev_map = {r["severity"]: r["n"] for r in threats}

                total = c.execute("SELECT COUNT(*) as n FROM threats WHERE status='active'").fetchone()["n"]
                today = c.execute(
                    "SELECT COUNT(*) as n FROM threats WHERE status='active' "
                    "AND date(detected_at)=date('now')"
                ).fetchone()["n"]

                last_job = c.execute(
                    "SELECT files_scanned, completed_at FROM scan_jobs "
                    "WHERE status='completed' ORDER BY id DESC LIMIT 1"
                ).fetchone()

                prot = self._setting("protection_status", "unknown")
                return {
                    "protection_status": prot,
                    "threats_by_severity": sev_map,
                    "total_active_threats": total,
                    "threats_today": today,
                    "files_scanned": last_job["files_scanned"] if last_job else 0,
                    "last_scan": (last_job["completed_at"] or "")[:16] if last_job else "Never",
                    "hostname": self._setting("hostname", ""),
                    "last_seen": self._setting("last_seen", ""),
                }
        except Exception:
            return {}

    def get_threats(self, status: str = "active", limit: int = 200) -> list:
        if not self.db_exists():
            return []
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT * FROM threats WHERE status=? ORDER BY detected_at DESC LIMIT ?",
                    (status, limit)
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def get_all_threats(self, limit: int = 200) -> list:
        if not self.db_exists():
            return []
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT * FROM threats ORDER BY detected_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def get_quarantine(self) -> list:
        if not self.db_exists():
            return []
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT q.*, t.name as threat_name FROM quarantine q "
                    "LEFT JOIN threats t ON t.id=q.threat_id "
                    "ORDER BY q.quarantined_at DESC"
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def get_scan_jobs(self, limit: int = 20) -> list:
        if not self.db_exists():
            return []
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def get_active_scan(self) -> dict | None:
        if not self.db_exists():
            return None
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT * FROM scan_jobs WHERE status='running' ORDER BY id DESC LIMIT 1"
                ).fetchone()
                return dict(row) if row else None
        except Exception:
            return None

    def queue_scan(self, scan_type: str, scan_path: str = "") -> bool:
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO scan_queue (scan_type, scan_path, status) VALUES (?,?,'pending')",
                    (scan_type, scan_path)
                )
                c.commit()
            return True
        except Exception:
            return False

    def restore_from_quarantine(self, qid: int) -> bool:
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT * FROM quarantine WHERE id=?", (qid,)
                ).fetchone()
                if not row:
                    return False
                os.rename(row["quarantine_path"], row["original_path"])
                if row["threat_id"]:
                    c.execute("UPDATE threats SET status='resolved', quarantine_path=NULL WHERE id=?",
                              (row["threat_id"],))
                c.execute("DELETE FROM quarantine WHERE id=?", (qid,))
                c.commit()
            return True
        except Exception:
            return False

    def delete_from_quarantine(self, qid: int) -> bool:
        try:
            with self._conn() as c:
                row = c.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
                if not row:
                    return False
                try:
                    os.remove(row["quarantine_path"])
                except Exception:
                    pass
                if row["threat_id"]:
                    c.execute("DELETE FROM threats WHERE id=?", (row["threat_id"],))
                c.execute("DELETE FROM quarantine WHERE id=?", (qid,))
                c.commit()
            return True
        except Exception:
            return False

    def resolve_threat(self, tid: int):
        try:
            with self._conn() as c:
                c.execute("UPDATE threats SET status='resolved' WHERE id=?", (tid,))
                c.commit()
        except Exception:
            pass

    def get_ioc_count(self) -> int:
        if not self.db_exists():
            return 0
        try:
            with self._conn() as c:
                return c.execute("SELECT COUNT(*) as n FROM ioc_hashes").fetchone()["n"]
        except Exception:
            return 0

# ── Shield image ──────────────────────────────────────────────────────────────
def make_shield(size: int, color: tuple, disabled=False) -> ctk.CTkImage:
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = size // 2, size // 2
    s = size
    shield = [
        (cx,          int(s*0.06)),
        (cx+int(s*0.40), int(s*0.20)),
        (cx+int(s*0.40), int(s*0.52)),
        (cx+int(s*0.28), int(s*0.76)),
        (cx,          int(s*0.94)),
        (cx-int(s*0.28), int(s*0.76)),
        (cx-int(s*0.40), int(s*0.52)),
        (cx-int(s*0.40), int(s*0.20)),
    ]
    draw.polygon(shield, fill=color + (255,))
    inner = [(x*0.80+cx*0.20, y*0.80+cy*0.20) for x, y in shield]
    draw.polygon(inner, fill=(255, 255, 255, 25))
    if disabled:
        lw = max(4, size // 16)
        draw.line([(cx-size//5, cy-size//5), (cx+size//5, cy+size//5)], fill=(220, 50, 50, 255), width=lw)
        draw.line([(cx+size//5, cy-size//5), (cx-size//5, cy+size//5)], fill=(220, 50, 50, 255), width=lw)
    else:
        lw = max(3, size // 20)
        draw.line([(cx-size//8, cy), (cx-size//24, cy+size//8), (cx+size//8, cy-size//10)],
                  fill=(255, 255, 255, 230), width=lw)
    return ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))


# ── Main Application ──────────────────────────────────────────────────────────
class AegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AegisEDR Security")
        self.geometry("960x640")
        self.minsize(820, 560)
        self.resizable(True, True)

        try:
            ico_candidates = [
                os.path.join(getattr(sys, "_MEIPASS", ""), "icon.ico"),
                os.path.join(os.path.dirname(__file__), "..", "assets", "icon.ico"),
                r"C:\Program Files\AegisEDR\icon.ico",
            ]
            ico = next((p for p in ico_candidates if os.path.isfile(p)), None)
            if ico:
                self.iconbitmap(ico)
        except Exception:
            pass

        self.db = LocalDB()
        self._stats   = {}
        self._threats = []
        self._scan_running = False
        self._active_filter = "active"

        self._build_ui()
        self._refresh()
        self._start_auto_refresh()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        sidebar = ctk.CTkFrame(self, width=210, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(10, weight=1)
        self.sidebar = sidebar

        ctk.CTkLabel(sidebar, text="  AegisEDR",
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color="#6366f1").grid(row=0, column=0, padx=20, pady=(24,2), sticky="w")
        ctk.CTkLabel(sidebar, text=f"  Standalone v{AGENT_VERSION}",
                     font=ctk.CTkFont(size=11), text_color="gray").grid(
            row=1, column=0, padx=20, pady=(0,20), sticky="w")

        nav_items = [
            ("  Dashboard",  "dashboard"),
            ("  Threats",    "threats"),
            ("  Scan",       "scan"),
            ("  Quarantine", "quarantine"),
            ("  Logs",       "logs"),
        ]
        if IS_ADMIN:
            nav_items.append(("  Settings", "settings"))

        self._nav_btns = {}
        for i, (label, key) in enumerate(nav_items):
            btn = ctk.CTkButton(
                sidebar, text=label, anchor="w",
                font=ctk.CTkFont(size=14),
                fg_color="transparent", hover_color="#374151",
                command=lambda k=key: self._show_page(k)
            )
            btn.grid(row=i+2, column=0, padx=10, pady=2, sticky="ew")
            self._nav_btns[key] = btn

        self.sidebar_status = ctk.CTkLabel(sidebar, text="● Starting...",
                                            font=ctk.CTkFont(size=12), text_color="gray")
        self.sidebar_status.grid(row=11, column=0, padx=20, pady=20, sticky="w")

        # Content area
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew")
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
        for frame in self._pages.values():
            frame.grid_remove()
        self._pages[key].grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        for k, btn in self._nav_btns.items():
            btn.configure(fg_color="#374151" if k == key else "transparent")
        if key == "logs":
            self._refresh_logs()
        elif key == "quarantine":
            self._refresh_quarantine()
        elif key == "scan":
            self._refresh_scan_history()

    # ── Dashboard ─────────────────────────────────────────────────────────────
    def _build_dashboard(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        self._pages["dashboard"] = f

        ctk.CTkLabel(f, text="Security Dashboard",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 16))

        # Status card
        status_card = ctk.CTkFrame(f, corner_radius=16, height=200)
        status_card.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        status_card.grid_columnconfigure(1, weight=1)
        status_card.grid_propagate(False)

        self.shield_lbl  = ctk.CTkLabel(status_card, text="")
        self.shield_lbl.grid(row=0, column=0, rowspan=3, padx=30, pady=20)

        self.status_title = ctk.CTkLabel(status_card, text="Starting...",
                                          font=ctk.CTkFont(size=26, weight="bold"))
        self.status_title.grid(row=0, column=1, sticky="sw", pady=(30, 0))

        self.status_sub = ctk.CTkLabel(status_card, text="Initializing protection engine...",
                                        font=ctk.CTkFont(size=14), text_color="gray")
        self.status_sub.grid(row=1, column=1, sticky="nw", pady=(4, 0))

        self.status_time = ctk.CTkLabel(status_card, text="",
                                         font=ctk.CTkFont(size=12), text_color="gray")
        self.status_time.grid(row=2, column=1, sticky="nw")

        # Stats row
        stats_f = ctk.CTkFrame(f, fg_color="transparent")
        stats_f.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 16))
        stats_f.grid_columnconfigure((0,1,2,3), weight=1)

        self._stat_cards = {}
        for i, (key, label, color) in enumerate([
            ("threats_today", "Threats Today",  "#ef4444"),
            ("total_threats", "Total Threats",  "#f97316"),
            ("files_scanned", "Last Scan Files","#6366f1"),
            ("last_scan",     "Last Scan",      "#10b981"),
        ]):
            card = ctk.CTkFrame(stats_f, corner_radius=12)
            card.grid(row=0, column=i, padx=5, sticky="ew")
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=11),
                         text_color="gray").grid(row=0, column=0, padx=14, pady=(12,0), sticky="w")
            val = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=20, weight="bold"),
                                text_color=color)
            val.grid(row=1, column=0, padx=14, pady=(2,12), sticky="w")
            self._stat_cards[key] = val

        # Actions
        act = ctk.CTkFrame(f, fg_color="transparent")
        act.grid(row=3, column=0, columnspan=2, sticky="ew")
        act.grid_columnconfigure((0,1,2), weight=1)

        ctk.CTkButton(act, text="Quick Scan", height=44,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=lambda: self._start_scan("quick")).grid(row=0, column=0, padx=(0,6), sticky="ew")
        ctk.CTkButton(act, text="Full Scan", height=44,
                      font=ctk.CTkFont(size=14), fg_color="#374151", hover_color="#4b5563",
                      command=lambda: self._start_scan("full")).grid(row=0, column=1, padx=6, sticky="ew")
        ctk.CTkButton(act, text="Scan Folder...", height=44,
                      font=ctk.CTkFont(size=14), fg_color="#1e293b", hover_color="#334155",
                      command=lambda: self._start_scan("custom")).grid(row=0, column=2, padx=(6,0), sticky="ew")

    # ── Threats ───────────────────────────────────────────────────────────────
    def _build_threats(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._pages["threats"] = f

        hdr = ctk.CTkFrame(f, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="Detected Threats",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, sticky="w")

        # Filter tabs
        filter_f = ctk.CTkFrame(f, fg_color="transparent")
        filter_f.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self._filter_btns = {}
        for i, (label, fkey) in enumerate([
            ("Active", "active"), ("Quarantined", "quarantined"), ("All", "all")
        ]):
            btn = ctk.CTkButton(filter_f, text=label, width=110, height=30,
                                fg_color="#374151" if i == 0 else "transparent",
                                hover_color="#374151",
                                command=lambda k=fkey: self._set_threat_filter(k))
            btn.grid(row=0, column=i, padx=(0 if i==0 else 4, 0))
            self._filter_btns[fkey] = btn

        self.threats_scroll = ctk.CTkScrollableFrame(f, corner_radius=12)
        self.threats_scroll.grid(row=2, column=0, sticky="nsew")
        self.threats_scroll.grid_columnconfigure(0, weight=1)
        self._threat_rows = []

    def _set_threat_filter(self, fkey: str):
        self._active_filter = fkey
        for k, btn in self._filter_btns.items():
            btn.configure(fg_color="#374151" if k == fkey else "transparent")
        self._refresh_threats_ui()

    def _refresh_threats_ui(self):
        for w in self._threat_rows:
            w.destroy()
        self._threat_rows = []

        fkey = self._active_filter
        if fkey == "all":
            threats = self.db.get_all_threats()
        elif fkey == "quarantined":
            threats = self.db.get_threats(status="quarantined")
        else:
            threats = self.db.get_threats(status="active")

        if not threats:
            lbl = ctk.CTkLabel(self.threats_scroll,
                               text="No threats detected  ✓",
                               font=ctk.CTkFont(size=15), text_color="#10b981")
            lbl.grid(row=0, column=0, pady=40)
            self._threat_rows.append(lbl)
            return

        SEV_COLOR = {"critical": "#ef4444", "high": "#f97316",
                     "medium":   "#eab308", "low":  "#6366f1"}

        for i, t in enumerate(threats):
            row = ctk.CTkFrame(self.threats_scroll, corner_radius=10, height=76)
            row.grid(row=i, column=0, sticky="ew", pady=4)
            row.grid_columnconfigure(1, weight=1)
            row.grid_propagate(False)

            sev   = t.get("severity", "low")
            color = SEV_COLOR.get(sev, "#6366f1")

            bar = ctk.CTkFrame(row, width=6, corner_radius=3, fg_color=color)
            bar.grid(row=0, column=0, rowspan=2, padx=(10,12), pady=10, sticky="ns")

            ctk.CTkLabel(row, text=t.get("name", "Unknown Threat"),
                         font=ctk.CTkFont(size=13, weight="bold"),
                         anchor="w").grid(row=0, column=1, sticky="sw", pady=(12,0))

            fp = (t.get("file_path") or "")[:65]
            ctk.CTkLabel(row, text=f"{(t.get('threat_type','') or '').upper()}  ·  {fp}",
                         font=ctk.CTkFont(size=11), text_color="gray",
                         anchor="w").grid(row=1, column=1, sticky="nw")

            ctk.CTkLabel(row, text=sev.upper(),
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=color).grid(row=0, column=2, padx=12, pady=(12,0), sticky="e")

            ts = (t.get("detected_at") or "")[:16]
            ctk.CTkLabel(row, text=ts, font=ctk.CTkFont(size=11),
                         text_color="gray").grid(row=1, column=2, padx=12, sticky="e")

            # Resolve button (active threats only)
            if t.get("status") == "active":
                ctk.CTkButton(row, text="Resolve", width=70, height=26,
                              fg_color="#374151", hover_color="#4b5563",
                              font=ctk.CTkFont(size=11),
                              command=lambda tid=t["id"]: self._resolve_threat(tid)
                              ).grid(row=0, column=3, padx=(0,12), pady=(12,0), sticky="e")

            self._threat_rows.append(row)

    def _resolve_threat(self, tid: int):
        self.db.resolve_threat(tid)
        self._refresh_threats_ui()

    # ── Scan ──────────────────────────────────────────────────────────────────
    def _build_scan(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(3, weight=1)
        self._pages["scan"] = f

        ctk.CTkLabel(f, text="Scan",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 16))

        # Scan type cards
        types_f = ctk.CTkFrame(f, fg_color="transparent")
        types_f.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        types_f.grid_columnconfigure((0,1,2), weight=1)

        for i, (label, stype, desc) in enumerate([
            ("Quick Scan",  "quick",  "Common locations\n~2-5 minutes"),
            ("Full Scan",   "full",   "Entire system\n~15-30 minutes"),
            ("Custom Scan", "custom", "Choose a folder\nAny location"),
        ]):
            card = ctk.CTkFrame(types_f, corner_radius=12, height=120)
            card.grid(row=0, column=i, padx=5, sticky="ew")
            card.grid_propagate(False)
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=label,
                         font=ctk.CTkFont(size=14, weight="bold")).grid(
                row=0, column=0, padx=16, pady=(18,2), sticky="w")
            ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(size=11),
                         text_color="gray").grid(row=1, column=0, padx=16, sticky="w")
            ctk.CTkButton(card, text="Start", height=28, width=80,
                          command=lambda s=stype: self._start_scan(s)).grid(
                row=2, column=0, padx=16, pady=(6,16), sticky="w")

        # Progress card
        prog_card = ctk.CTkFrame(f, corner_radius=12)
        prog_card.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        prog_card.grid_columnconfigure(0, weight=1)

        self.scan_status_lbl = ctk.CTkLabel(prog_card, text="No scan running",
                                             font=ctk.CTkFont(size=14))
        self.scan_status_lbl.grid(row=0, column=0, padx=20, pady=(16, 8), sticky="w")

        self.scan_progress = ctk.CTkProgressBar(prog_card, height=10)
        self.scan_progress.grid(row=1, column=0, padx=20, pady=(0, 6), sticky="ew")
        self.scan_progress.set(0)

        self.scan_file_lbl = ctk.CTkLabel(prog_card, text="",
                                           font=ctk.CTkFont(size=11), text_color="gray")
        self.scan_file_lbl.grid(row=2, column=0, padx=20, pady=(0, 16), sticky="w")

        # Scan history
        ctk.CTkLabel(f, text="Recent Scans",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(
            row=3, column=0, sticky="w", pady=(0, 8))

        self.scan_history_scroll = ctk.CTkScrollableFrame(f, corner_radius=12, height=160)
        self.scan_history_scroll.grid(row=4, column=0, sticky="ew")
        self.scan_history_scroll.grid_columnconfigure(0, weight=1)

    def _start_scan(self, scan_type: str):
        scan_path = ""
        if scan_type == "custom":
            root2 = tk.Tk()
            root2.withdraw()
            root2.attributes("-topmost", True)
            scan_path = filedialog.askdirectory(title="Select folder to scan")
            root2.destroy()
            if not scan_path:
                return

        self._show_page("scan")
        self.db.queue_scan(scan_type, scan_path)
        self.scan_status_lbl.configure(text=f"Queued {scan_type} scan — agent will start shortly...")
        self.scan_progress.set(0)
        self._poll_scan_progress()

    def _poll_scan_progress(self):
        def _poll():
            while True:
                active = self.db.get_active_scan()
                if active:
                    scanned = active.get("files_scanned", 0)
                    found   = active.get("threats_found", 0)
                    self.after(0, lambda s=scanned, f=found: (
                        self.scan_status_lbl.configure(
                            text=f"Scanning... {s} files checked, {f} threat(s) found"),
                        self.scan_progress.set(0.5)
                    ))
                    time.sleep(2)
                else:
                    jobs = self.db.get_scan_jobs(limit=1)
                    if jobs and jobs[0]["status"] == "completed":
                        j = jobs[0]
                        msg = (f"Scan complete — {j['files_scanned']} files, "
                               f"{j['threats_found']} threat(s) found")
                        self.after(0, lambda m=msg: (
                            self.scan_status_lbl.configure(text=m),
                            self.scan_file_lbl.configure(text=""),
                            self.scan_progress.set(1.0),
                            self._refresh_scan_history(),
                            self._refresh()
                        ))
                    elif jobs and jobs[0]["status"] == "failed":
                        self.after(0, lambda: self.scan_status_lbl.configure(
                            text=f"Scan failed: {jobs[0].get('error_msg','')}"))
                    break
                time.sleep(2)

        threading.Thread(target=_poll, daemon=True).start()

    def _refresh_scan_history(self):
        for w in self.scan_history_scroll.winfo_children():
            w.destroy()
        jobs = self.db.get_scan_jobs(limit=10)
        if not jobs:
            ctk.CTkLabel(self.scan_history_scroll, text="No scans yet",
                         text_color="gray").grid(row=0, column=0, pady=12)
            return
        STATUS_COLOR = {"completed": "#10b981", "running": "#6366f1",
                        "failed": "#ef4444", "pending": "#eab308"}
        for i, j in enumerate(jobs):
            row = ctk.CTkFrame(self.scan_history_scroll, corner_radius=8, height=44)
            row.grid(row=i, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)
            row.grid_propagate(False)
            sc = STATUS_COLOR.get(j.get("status",""), "gray")
            ctk.CTkLabel(row, text=f"  {(j.get('scan_type','') or '').capitalize()} Scan",
                         font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=8, sticky="w")
            info = (f"{j.get('files_scanned',0)} files  ·  "
                    f"{j.get('threats_found',0)} threats  ·  "
                    f"{(j.get('completed_at') or j.get('started_at') or '')[:16]}")
            ctk.CTkLabel(row, text=info, font=ctk.CTkFont(size=11),
                         text_color="gray").grid(row=0, column=1, sticky="w")
            ctk.CTkLabel(row, text=f"{j.get('status','').upper()}  ",
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=sc).grid(row=0, column=2, padx=8)

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

    def _refresh_quarantine(self):
        for w in self.quar_scroll.winfo_children():
            w.destroy()
        items = self.db.get_quarantine()
        if not items:
            ctk.CTkLabel(self.quar_scroll, text="Quarantine is empty  ✓",
                         font=ctk.CTkFont(size=15), text_color="#10b981").grid(
                row=0, column=0, pady=40)
            return
        for i, q in enumerate(items):
            row = ctk.CTkFrame(self.quar_scroll, corner_radius=10, height=68)
            row.grid(row=i, column=0, sticky="ew", pady=4)
            row.grid_columnconfigure(1, weight=1)
            row.grid_propagate(False)

            fname = os.path.basename(q.get("original_path") or "")
            ctk.CTkLabel(row, text=f"  {fname}",
                         font=ctk.CTkFont(size=13, weight="bold"),
                         anchor="w").grid(row=0, column=0, sticky="sw", pady=(12,0))

            detail = f"Original: {q.get('original_path','')[:60]}  ·  {(q.get('quarantined_at') or '')[:16]}"
            ctk.CTkLabel(row, text=f"  {detail}", font=ctk.CTkFont(size=11),
                         text_color="gray", anchor="w").grid(row=1, column=0, columnspan=2, sticky="nw")

            btns = ctk.CTkFrame(row, fg_color="transparent")
            btns.grid(row=0, column=2, padx=10, pady=(12,0), sticky="e")
            qid = q["id"]
            ctk.CTkButton(btns, text="Restore", width=72, height=26,
                          fg_color="#374151", hover_color="#4b5563",
                          font=ctk.CTkFont(size=11),
                          command=lambda i=qid: self._restore_quarantine(i)).grid(row=0, column=0, padx=(0,4))
            ctk.CTkButton(btns, text="Delete", width=66, height=26,
                          fg_color="#7f1d1d", hover_color="#991b1b",
                          font=ctk.CTkFont(size=11),
                          command=lambda i=qid: self._delete_quarantine(i)).grid(row=0, column=1)

    def _restore_quarantine(self, qid: int):
        if self.db.restore_from_quarantine(qid):
            self._refresh_quarantine()

    def _delete_quarantine(self, qid: int):
        if self.db.delete_from_quarantine(qid):
            self._refresh_quarantine()

    # ── Logs ──────────────────────────────────────────────────────────────────
    def _build_logs(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(1, weight=1)
        self._pages["logs"] = f

        hdr = ctk.CTkFrame(f, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="Agent Logs",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(hdr, text="Refresh", width=90,
                      command=self._refresh_logs).grid(row=0, column=1, sticky="e")
        ctk.CTkButton(hdr, text="Open File", width=90,
                      fg_color="#374151", hover_color="#4b5563",
                      command=lambda: os.startfile(LOG_PATH) if os.path.isfile(LOG_PATH) else None
                      ).grid(row=0, column=2, padx=(8,0), sticky="e")

        self.log_box = ctk.CTkTextbox(f, corner_radius=12,
                                       font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.grid(row=1, column=0, sticky="nsew")

    def _refresh_logs(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        try:
            with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            self.log_box.insert("end", "".join(lines[-300:]))
            self.log_box.see("end")
        except FileNotFoundError:
            self.log_box.insert("end", f"Log file not found: {LOG_PATH}\n"
                                       "Start the AegisEDR-Agent service to generate logs.")
        self.log_box.configure(state="disabled")

    # ── Settings ──────────────────────────────────────────────────────────────
    def _build_settings(self):
        f = ctk.CTkFrame(self.content, fg_color="transparent")
        f.grid_columnconfigure(0, weight=1)
        self._pages["settings"] = f

        ctk.CTkLabel(f, text="Settings  [Admin]",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 20))

        # Protection toggle
        p = ctk.CTkFrame(f, corner_radius=12)
        p.grid(row=1, column=0, sticky="ew", pady=(0,12))
        p.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(p, text="Real-time Protection",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=20, pady=(16,4), sticky="w")
        ctk.CTkLabel(p, text="Monitor file system for threats in real-time.",
                     font=ctk.CTkFont(size=12), text_color="gray").grid(row=1, column=0, padx=20, pady=(0,8), sticky="w")
        pb = ctk.CTkFrame(p, fg_color="transparent")
        pb.grid(row=2, column=0, padx=20, pady=(0,16), sticky="w")
        ctk.CTkButton(pb, text="Enable", width=130, fg_color="#10b981", hover_color="#059669",
                      command=self._enable_protection).grid(row=0, column=0, padx=(0,8))
        ctk.CTkButton(pb, text="Disable", width=130, fg_color="#ef4444", hover_color="#dc2626",
                      command=self._disable_protection).grid(row=0, column=1)

        # Windows Defender
        d = ctk.CTkFrame(f, corner_radius=12)
        d.grid(row=2, column=0, sticky="ew", pady=(0,12))
        d.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(d, text="Windows Defender",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=20, pady=(16,4), sticky="w")
        ctk.CTkLabel(d, text="Disable Defender so AegisEDR can replace it. Requires reboot to take full effect.",
                     font=ctk.CTkFont(size=12), text_color="gray").grid(row=1, column=0, padx=20, pady=(0,8), sticky="w")
        db_btns = ctk.CTkFrame(d, fg_color="transparent")
        db_btns.grid(row=2, column=0, padx=20, pady=(0,16), sticky="w")
        ctk.CTkButton(db_btns, text="Disable Defender", width=160,
                      fg_color="#7c3aed", hover_color="#6d28d9",
                      command=self._disable_defender).grid(row=0, column=0, padx=(0,8))
        ctk.CTkButton(db_btns, text="Re-enable", width=130,
                      fg_color="#374151", hover_color="#4b5563",
                      command=self._enable_defender).grid(row=0, column=1)

        # Agent service
        s = ctk.CTkFrame(f, corner_radius=12)
        s.grid(row=3, column=0, sticky="ew", pady=(0,12))
        s.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(s, text="Agent Service",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=20, pady=(16,4), sticky="w")
        sb = ctk.CTkFrame(s, fg_color="transparent")
        sb.grid(row=1, column=0, padx=20, pady=(0,16), sticky="w")
        ctk.CTkButton(sb, text="Restart Agent", width=130,
                      command=self._restart_agent).grid(row=0, column=0, padx=(0,8))
        ctk.CTkButton(sb, text="Open Data Folder", width=150,
                      fg_color="#374151", hover_color="#4b5563",
                      command=lambda: os.startfile(DATA_DIR)).grid(row=0, column=1)

        # Info card
        info = ctk.CTkFrame(f, corner_radius=12)
        info.grid(row=4, column=0, sticky="ew")
        info.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(info, text="About",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=20, pady=(16,8), sticky="w")
        self.info_lbl = ctk.CTkLabel(info, text=self._get_info_text(),
                                      font=ctk.CTkFont(size=12), text_color="gray",
                                      justify="left")
        self.info_lbl.grid(row=1, column=0, padx=20, pady=(0,16), sticky="w")

    def _get_info_text(self) -> str:
        ioc_count = self.db.get_ioc_count()
        return (f"AegisEDR Standalone v{AGENT_VERSION}\n"
                f"Data: {DATA_DIR}\n"
                f"IoC signatures: {ioc_count}\n"
                f"Hostname: {self.db._setting('hostname', 'unknown')}")

    def _enable_protection(self):
        try:
            with self.db._conn() as c:
                c.execute("INSERT OR REPLACE INTO settings VALUES ('realtime_enabled','1')")
                c.commit()
        except Exception:
            pass
        subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    def _disable_protection(self):
        try:
            with self.db._conn() as c:
                c.execute("INSERT OR REPLACE INTO settings VALUES ('realtime_enabled','0')")
                c.commit()
        except Exception:
            pass

    def _disable_defender(self):
        def _run():
            cmds = [
                'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Force | Out-Null',
                'New-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" -Force | Out-Null',
                'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force',
                'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force',
                'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force',
                'Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -ErrorAction SilentlyContinue',
            ]
            for cmd in cmds:
                subprocess.run(["powershell", "-NonInteractive", "-Command", cmd],
                               capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        threading.Thread(target=_run, daemon=True).start()

    def _enable_defender(self):
        subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "Set-MpPreference -DisableRealtimeMonitoring $false "
             "-DisableIOAVProtection $false -ErrorAction SilentlyContinue"],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW
        )

    def _restart_agent(self):
        subprocess.run(["schtasks", "/End", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(1)
        subprocess.run(["schtasks", "/Run", "/TN", "AegisEDRAgent"],
                       capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

    # ── Refresh logic ─────────────────────────────────────────────────────────
    def _refresh(self):
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _do_refresh(self):
        if not self.db.db_exists():
            self.after(0, self._set_status_no_agent)
            return
        stats   = self.db.get_stats()
        threats = self.db.get_threats(status="active")
        self._stats   = stats
        self._threats = threats
        self.after(0, lambda: self._update_ui(stats, threats))

    def _set_status_no_agent(self):
        shield = make_shield(96, (100, 100, 100), disabled=True)
        self.shield_lbl.configure(image=shield)
        self.status_title.configure(text="Agent Not Running", text_color="#9ca3af")
        self.status_sub.configure(text="Start the AegisEDR-Agent scheduled task to enable protection.")
        self.sidebar_status.configure(text="● Agent offline", text_color="#9ca3af")

    def _update_ui(self, stats: dict, threats: list):
        prot   = stats.get("protection_status", "unknown")
        total  = stats.get("total_active_threats", 0)
        today  = stats.get("threats_today", 0)

        if prot in ("active", "limited") and total == 0:
            color, title, sub, sc = (16,185,129), "You're Protected", "All systems secure.", "protected"
        elif total > 0:
            color, title, sub, sc = (239,68,68), f"{total} Threat(s) Detected!", "Immediate action required.", "threat"
        elif prot == "stopped":
            color, title, sub, sc = (100,100,100), "Protection Stopped", "Restart the agent service.", "stopped"
        elif prot == "starting":
            color, title, sub, sc = (234,179,8), "Starting...", "Initializing protection engine.", "starting"
        else:
            color, title, sub, sc = (148,163,184), "Agent Offline", "Start AegisEDR-Agent service.", "offline"

        shield = make_shield(96, color, disabled=(sc in ("stopped","offline")))
        self.shield_lbl.configure(image=shield)
        self.status_title.configure(
            text=title, text_color=f"#{color[0]:02x}{color[1]:02x}{color[2]:02x}")
        self.status_sub.configure(text=sub)
        self.status_time.configure(
            text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

        scolors = {"protected":"#10b981","threat":"#ef4444",
                   "stopped":"#9ca3af","starting":"#eab308","offline":"#9ca3af"}
        self.sidebar_status.configure(
            text=f"● {title}",
            text_color=scolors.get(sc, "gray"))

        sev = stats.get("threats_by_severity", {})
        self._stat_cards["threats_today"].configure(text=str(today))
        self._stat_cards["total_threats"].configure(text=str(total))
        self._stat_cards["files_scanned"].configure(text=str(stats.get("files_scanned", "—")))
        self._stat_cards["last_scan"].configure(text=(stats.get("last_scan") or "Never")[:10])

        self._threats = threats
        self._refresh_threats_ui()

    def _start_auto_refresh(self):
        def _loop():
            while True:
                time.sleep(15)
                self._refresh()
        threading.Thread(target=_loop, daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    app = AegisApp()
    app.mainloop()

if __name__ == "__main__":
    main()
