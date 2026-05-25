import sys
import json
import time
import socket
import ctypes
import threading
import subprocess
import urllib.request
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

import applog
import wgapi
import settings as appsettings
from settings import DnsEntry
from monitor import AutoReconnectMonitor

log = applog.get("ui")


COLOR_BG = "#1e1f22"
COLOR_PANEL = "#2b2d31"
COLOR_HOVER = "#34363c"
COLOR_SEL = "#3b3d44"
COLOR_PRIMARY = "#2c7ef0"
COLOR_PRIMARY_HOVER = "#4391ff"
COLOR_DANGER = "#b8443a"
COLOR_DANGER_HOVER = "#d35248"
COLOR_OK = "#4ade80"
COLOR_MUTED = "#9da0a8"
COLOR_TEXT = "#e6e6e6"
FONT_FAMILY = "Segoe UI"


def _lighten(hexcol: str, amt: float = 0.18) -> str:
    try:
        h = hexcol.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        r = min(255, int(r + (255 - r) * amt))
        g = min(255, int(g + (255 - g) * amt))
        b = min(255, int(b + (255 - b) * amt))
        return f"#{r:02x}{g:02x}{b:02x}"
    except Exception:
        return hexcol


def _apply_theme() -> None:
    """Pull font + accent from settings into the module-level constants before
    any widget is built (Tk reads these at widget-creation time)."""
    global FONT_FAMILY, COLOR_PRIMARY, COLOR_PRIMARY_HOVER
    ui = appsettings.get_ui()
    if ui.font_family:
        FONT_FAMILY = ui.font_family
    if ui.accent:
        COLOR_PRIMARY = ui.accent
        COLOR_PRIMARY_HOVER = _lighten(ui.accent, 0.18)


def fmt_bytes(n: float) -> str:
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PiB"


def fmt_rate(bps: float) -> str:
    return fmt_bytes(bps) + "/s"


def fmt_duration(secs: int) -> str:
    if secs <= 0:
        return "0s"
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h: return f"{h}h {m}m {s}s"
    if m: return f"{m}m {s}s"
    return f"{s}s"


def ping_ms(host: str, timeout_ms: int = 1200) -> float:
    """Single ICMP ping; returns latency in ms, or -1.0 on failure."""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return -1.0
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), ip],
            capture_output=True, text=True, timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in r.stdout.splitlines():
            low = line.lower()
            if "time=" in low or "time<" in low:
                seg = low.split("time")[1]
                num = ""
                for ch in seg[1:]:
                    if ch.isdigit() or ch == ".":
                        num += ch
                    elif num:
                        break
                if num:
                    return float(num)
        return -1.0
    except Exception:
        return -1.0


def lookup_country(ip: str) -> tuple[str, str]:
    """(country_name, country_code) for an IP. Tries HTTPS ipwho.is first,
    then HTTP ip-api.com. Runs through the active tunnel, so it can fail if the
    exit blocks the geo service — every attempt is logged to app.log."""
    providers = (
        ("https://ipwho.is/{}".format(ip), "country", "country_code"),
        ("http://ip-api.com/json/{}?fields=status,country,countryCode".format(ip),
         "country", "countryCode"),
    )
    for url, ckey, codekey in providers:
        host = url.split("/")[2]
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "localwg/1.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            name, code = data.get(ckey, ""), data.get(codekey, "")
            if name or code:
                log.info("geo %s -> %s (%s) via %s", ip, name, code, host)
                return name, code
            log.warning("geo %s: %s returned no country (%s)", ip, host, data)
        except Exception as e:
            log.warning("geo %s: %s failed: %s", ip, host, e)
    return "", ""


def build_tray_image(active: bool, up_on: bool, down_on: bool):
    """64x64 icon: an up arrow (upload) over a down arrow (download).
    Arrows light up green/blue when that direction has traffic."""
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (30, 31, 34, 255))
    d = ImageDraw.Draw(img)
    idle = (90, 92, 100)
    up = (74, 222, 128) if (active and up_on) else idle
    dn = (67, 145, 255) if (active and down_on) else idle
    # upload arrow (top half, pointing up)
    d.polygon([(32, 5), (53, 26), (39, 26), (39, 30), (25, 30), (25, 26), (11, 26)], fill=up)
    # download arrow (bottom half, pointing down)
    d.polygon([(32, 59), (53, 38), (39, 38), (39, 34), (25, 34), (25, 38), (11, 38)], fill=dn)
    return img


class StatsPoller(threading.Thread):
    """Polls is_active + get_stats for the currently selected tunnel in background."""
    def __init__(self):
        super().__init__(daemon=True)
        self._stop_evt = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._tunnel: str | None = None
        self._snapshot: dict = {"active": False, "stats": None, "ts": 0.0, "tunnel": None}

    def set_tunnel(self, name: str | None):
        with self._lock:
            if self._tunnel != name:
                self._tunnel = name
                self._snapshot = {"active": False, "stats": None, "ts": 0.0, "tunnel": name}
        self._wake.set()

    def poke(self):
        self._wake.set()

    def stop(self):
        self._stop_evt.set()
        self._wake.set()

    def get_snapshot(self) -> dict:
        with self._lock:
            return dict(self._snapshot)

    def run(self):
        while not self._stop_evt.is_set():
            with self._lock:
                t = self._tunnel
            if t:
                try:
                    active = wgapi.is_active(t)
                    stats = wgapi.get_stats(t) if active else None
                    with self._lock:
                        if self._tunnel == t:
                            self._snapshot = {
                                "active": active, "stats": stats,
                                "ts": time.time(), "tunnel": t,
                            }
                except Exception:
                    pass
            self._wake.wait(1.0)
            self._wake.clear()


class PingThread(threading.Thread):
    def __init__(self, host: str, callback):
        super().__init__(daemon=True)
        self.host = host
        self.callback = callback
        self._stop_evt = threading.Event()

    def stop(self):
        self._stop_evt.set()

    def run(self):
        while not self._stop_evt.is_set():
            ms = ping_ms(self.host, timeout_ms=1500)
            if not self._stop_evt.is_set():
                try:
                    self.callback(self.host, ms)
                except Exception:
                    return
            self._stop_evt.wait(1.0)


class TunnelDialog(ctk.CTkToplevel):
    def __init__(self, parent, name: str = "", config: str = "", edit_mode: bool = False):
        super().__init__(parent)
        self.title("Edit Tunnel" if edit_mode else "Add Tunnel")
        self.geometry("620x520")
        self.configure(fg_color=COLOR_BG)
        self.edit_mode = edit_mode
        self.result: tuple[str, str] | None = None

        self.transient(parent)
        self.grab_set()

        ctk.CTkLabel(self, text="Name", anchor="w").pack(fill="x", padx=20, pady=(20, 4))
        self.name_in = ctk.CTkEntry(self, height=34)
        self.name_in.insert(0, name)
        if edit_mode:
            self.name_in.configure(state="disabled")
        self.name_in.pack(fill="x", padx=20)

        head = ctk.CTkFrame(self, fg_color="transparent")
        head.pack(fill="x", padx=20, pady=(14, 4))
        ctk.CTkLabel(head, text="Configuration (.conf)", anchor="w").pack(side="left")
        if not edit_mode:
            ctk.CTkButton(head, text="Import from file…", width=140, height=28,
                          fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                          command=self._import).pack(side="right")

        self.cfg_in = ctk.CTkTextbox(self, font=(FONT_FAMILY, 11), wrap="none")
        self.cfg_in.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        if config:
            self.cfg_in.insert("1.0", config)
        else:
            self.cfg_in.insert("1.0",
                "[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n"
                "[Peer]\nPublicKey = ...\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n"
                "PersistentKeepalive = 25\n"
            )

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=20, pady=(0, 16))
        ctk.CTkButton(btns, text="Cancel", width=90, height=34,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=self._cancel).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btns, text="Save", width=110, height=34,
                      fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
                      command=self._save).pack(side="right")

        self.bind("<Escape>", lambda e: self._cancel())

    def _import(self):
        path = filedialog.askopenfilename(
            parent=self, title="Import WireGuard config",
            filetypes=[("Config files", "*.conf"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except Exception as e:
            messagebox.showerror("Import failed", str(e), parent=self)
            return
        self.cfg_in.delete("1.0", "end")
        self.cfg_in.insert("1.0", text)
        if not self.name_in.get().strip() and not self.edit_mode:
            self.name_in.configure(state="normal")
            self.name_in.delete(0, "end")
            self.name_in.insert(0, Path(path).stem)

    def _save(self):
        name = self.name_in.get().strip()
        cfg = self.cfg_in.get("1.0", "end").rstrip() + "\n"
        if not name or not cfg.strip():
            messagebox.showwarning("Missing", "Name and config required", parent=self)
            return
        self.result = (name, cfg)
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, parent, tunnel_name: str | None = None):
        super().__init__(parent)
        self.title("Settings" + (f" — {tunnel_name}" if tunnel_name else ""))
        self.geometry("520x760")
        self.configure(fg_color=COLOR_BG)
        self.tunnel_name = tunnel_name
        self.transient(parent)
        self.grab_set()
        self.result_saved = False

        # Load current effective values
        if tunnel_name:
            self.current = appsettings.get_auto_reconnect_for(tunnel_name)
            s = appsettings.load()
            override_exists = "auto_reconnect" in s.per_tunnel.get(tunnel_name, {})
        else:
            s = appsettings.load()
            self.current = s.auto_reconnect
            override_exists = False

        ctk.CTkLabel(self, text="Auto-reconnect", font=(FONT_FAMILY, 16, "bold"),
                     anchor="w").pack(fill="x", padx=24, pady=(20, 4))
        ctk.CTkLabel(self,
                     text="Reconnect when download speed stays below a threshold.",
                     text_color=COLOR_MUTED, anchor="w", justify="left",
                     wraplength=460).pack(fill="x", padx=24, pady=(0, 14))

        self.enabled_var = ctk.BooleanVar(value=self.current.enabled)
        ctk.CTkCheckBox(self, text="Enable auto-reconnect",
                        variable=self.enabled_var,
                        fg_color=COLOR_PRIMARY,
                        hover_color=COLOR_PRIMARY_HOVER).pack(
            anchor="w", padx=24, pady=4)

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="x", padx=24, pady=10)
        grid.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(grid, text="Min download speed (KB/s)").grid(
            row=0, column=0, sticky="w", pady=6)
        self.min_kbps_in = ctk.CTkEntry(grid, width=120)
        self.min_kbps_in.insert(0, str(self.current.min_kbps))
        self.min_kbps_in.grid(row=0, column=1, sticky="w", pady=6, padx=8)

        ctk.CTkLabel(grid, text="Window length (seconds)").grid(
            row=1, column=0, sticky="w", pady=6)
        self.window_in = ctk.CTkEntry(grid, width=120)
        self.window_in.insert(0, str(self.current.window_sec))
        self.window_in.grid(row=1, column=1, sticky="w", pady=6, padx=8)

        ctk.CTkLabel(grid, text="Reconnect delay (seconds)").grid(
            row=2, column=0, sticky="w", pady=6)
        self.delay_in = ctk.CTkEntry(grid, width=120)
        self.delay_in.insert(0, str(self.current.delay_sec))
        self.delay_in.grid(row=2, column=1, sticky="w", pady=6, padx=8)

        if tunnel_name:
            self.override_var = ctk.BooleanVar(value=override_exists)
            ctk.CTkCheckBox(self,
                            text=f"Override global settings for this tunnel ('{tunnel_name}')",
                            variable=self.override_var,
                            fg_color=COLOR_PRIMARY,
                            hover_color=COLOR_PRIMARY_HOVER).pack(
                anchor="w", padx=24, pady=(8, 0))

        # --- Feature toggles ---
        ui = appsettings.get_ui()
        ctk.CTkLabel(self, text="Features", font=(FONT_FAMILY, 16, "bold"),
                     anchor="w").pack(fill="x", padx=24, pady=(18, 4))
        self.dns_feat_var = ctk.BooleanVar(value=ui.dns_changer_enabled)
        ctk.CTkCheckBox(self, text="DNS changer on main page",
                        variable=self.dns_feat_var, fg_color=COLOR_PRIMARY,
                        hover_color=COLOR_PRIMARY_HOVER).pack(anchor="w", padx=24, pady=3)
        self.country_var = ctk.BooleanVar(value=ui.show_country)
        ctk.CTkCheckBox(self, text="Show server country",
                        variable=self.country_var, fg_color=COLOR_PRIMARY,
                        hover_color=COLOR_PRIMARY_HOVER).pack(anchor="w", padx=24, pady=3)
        self.tray_var = ctk.BooleanVar(value=ui.tray_enabled)
        ctk.CTkCheckBox(self, text="System tray icon (applies after restart)",
                        variable=self.tray_var, fg_color=COLOR_PRIMARY,
                        hover_color=COLOR_PRIMARY_HOVER).pack(anchor="w", padx=24, pady=3)
        ctk.CTkButton(self, text="Manage DNS list…", width=160, height=30,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=lambda: DnsManagerDialog(self)).pack(
            anchor="w", padx=24, pady=(8, 0))

        # --- Appearance (applies on restart) ---
        ctk.CTkLabel(self, text="Appearance  (applies on restart)",
                     font=(FONT_FAMILY, 16, "bold"), anchor="w").pack(
            fill="x", padx=24, pady=(16, 4))
        appr = ctk.CTkFrame(self, fg_color="transparent")
        appr.pack(fill="x", padx=24)
        ctk.CTkLabel(appr, text="Font").grid(row=0, column=0, sticky="w", pady=6)
        self.font_var = ctk.StringVar(value=ui.font_family)
        ctk.CTkOptionMenu(appr, variable=self.font_var,
                          values=appsettings.FONT_CHOICES, width=240,
                          fg_color=COLOR_SEL, button_color=COLOR_SEL,
                          button_hover_color=COLOR_HOVER,
                          dropdown_fg_color=COLOR_PANEL).grid(
            row=0, column=1, sticky="w", padx=8, pady=6)
        ctk.CTkLabel(appr, text="Accent color").grid(row=1, column=0, sticky="w", pady=6)
        self._accent_map = {n: c for n, c in appsettings.ACCENT_CHOICES}
        cur_accent = next((n for n, c in appsettings.ACCENT_CHOICES if c == ui.accent),
                          appsettings.ACCENT_CHOICES[0][0])
        self.accent_var = ctk.StringVar(value=cur_accent)
        ctk.CTkOptionMenu(appr, variable=self.accent_var,
                          values=[n for n, _ in appsettings.ACCENT_CHOICES], width=240,
                          fg_color=COLOR_SEL, button_color=COLOR_SEL,
                          button_hover_color=COLOR_HOVER,
                          dropdown_fg_color=COLOR_PANEL).grid(
            row=1, column=1, sticky="w", padx=8, pady=6)

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(18, 16), side="bottom")
        ctk.CTkButton(btns, text="Cancel", width=100, height=34,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=self.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btns, text="Save", width=120, height=34,
                      fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
                      command=self._save).pack(side="right")

        self.bind("<Escape>", lambda e: self.destroy())

    def _save(self):
        try:
            min_kbps = max(0, int(self.min_kbps_in.get().strip() or "0"))
            window = max(1, int(self.window_in.get().strip() or "1"))
            delay = max(0, int(self.delay_in.get().strip() or "0"))
        except ValueError:
            messagebox.showwarning("Invalid", "Numbers required for thresholds.",
                                    parent=self)
            return
        ar = appsettings.AutoReconnect(
            enabled=self.enabled_var.get(),
            min_kbps=min_kbps,
            window_sec=window,
            delay_sec=delay,
        )
        if self.tunnel_name:
            if getattr(self, "override_var", None) and self.override_var.get():
                appsettings.set_auto_reconnect_per_tunnel(self.tunnel_name, ar)
            else:
                appsettings.set_auto_reconnect_per_tunnel(self.tunnel_name, None)
                # If they don't override, the global values should reflect what's shown
                appsettings.set_auto_reconnect_global(ar)
        else:
            appsettings.set_auto_reconnect_global(ar)
        ui = appsettings.get_ui()
        ui.dns_changer_enabled = self.dns_feat_var.get()
        ui.show_country = self.country_var.get()
        ui.tray_enabled = self.tray_var.get()
        ui.font_family = self.font_var.get()
        ui.accent = self._accent_map.get(self.accent_var.get(), ui.accent)
        appsettings.set_ui(ui)
        self.result_saved = True
        self.destroy()


class DnsManagerDialog(ctk.CTkToplevel):
    """Add / edit / delete / enable DNS entries inline."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Manage DNS list")
        self.geometry("560x560")
        self.configure(fg_color=COLOR_BG)
        self.transient(parent)
        self.grab_set()
        self.changed = False
        self._rows: list[list] = []

        ctk.CTkLabel(self, text="DNS servers", font=(FONT_FAMILY, 16, "bold"),
                     anchor="w").pack(fill="x", padx=20, pady=(18, 2))
        ctk.CTkLabel(self, text="Toggle, rename, edit servers (comma-separated), add or delete.",
                     text_color=COLOR_MUTED, anchor="w").pack(fill="x", padx=20, pady=(0, 8))

        self.scroll = ctk.CTkScrollableFrame(self, fg_color=COLOR_PANEL)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=(4, 8))
        for e in appsettings.get_dns_catalog():
            self._add_row(e)

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=20, pady=(0, 16))
        ctk.CTkButton(btns, text="+ Add", width=90, fg_color=COLOR_SEL,
                      hover_color=COLOR_HOVER,
                      command=lambda: self._add_row(None)).pack(side="left")
        ctk.CTkButton(btns, text="Save", width=110, fg_color=COLOR_PRIMARY,
                      hover_color=COLOR_PRIMARY_HOVER,
                      command=self._save).pack(side="right")
        ctk.CTkButton(btns, text="Cancel", width=90, fg_color=COLOR_SEL,
                      hover_color=COLOR_HOVER,
                      command=self.destroy).pack(side="right", padx=(0, 8))
        self.bind("<Escape>", lambda e: self.destroy())

    def _add_row(self, entry):
        row = ctk.CTkFrame(self.scroll, fg_color="transparent")
        row.pack(fill="x", pady=3)
        en = ctk.BooleanVar(value=(entry.enabled if entry else True))
        ctk.CTkCheckBox(row, text="", width=24, variable=en,
                        fg_color=COLOR_PRIMARY,
                        hover_color=COLOR_PRIMARY_HOVER).pack(side="left")
        name = ctk.CTkEntry(row, width=150, placeholder_text="Name")
        name.pack(side="left", padx=(2, 4))
        servers = ctk.CTkEntry(row, placeholder_text="1.1.1.1, 1.0.0.1")
        servers.pack(side="left", fill="x", expand=True, padx=(0, 4))
        if entry:
            name.insert(0, entry.name)
            servers.insert(0, ", ".join(entry.servers))
        rec = [en, name, servers, row]
        ctk.CTkButton(row, text="✕", width=30, fg_color=COLOR_DANGER,
                      hover_color=COLOR_DANGER_HOVER,
                      command=lambda: self._del_row(rec)).pack(side="left")
        self._rows.append(rec)

    def _del_row(self, rec):
        rec[3].destroy()
        if rec in self._rows:
            self._rows.remove(rec)

    def _save(self):
        entries = []
        for en, name, servers, _ in self._rows:
            nm = name.get().strip()
            srv = [s.strip() for s in servers.get().replace(";", ",").split(",")
                   if s.strip()]
            if nm and srv:
                entries.append(DnsEntry(nm, srv, bool(en.get())))
        appsettings.save_dns_catalog(entries)
        self.changed = True
        self.destroy()


class SplitConfigDialog(ctk.CTkToplevel):
    """Per-tunnel split routing: off / exclude (blacklist) / include (whitelist)."""
    MODES = ["Off", "Exclude (bypass)", "Include (only)"]
    _MAP = {"Off": "off", "Exclude (bypass)": "exclude", "Include (only)": "include"}
    _RMAP = {v: k for k, v in _MAP.items()}

    def __init__(self, parent, tunnel_name: str):
        super().__init__(parent)
        self.title(f"Split routing — {tunnel_name}")
        self.geometry("560x520")
        self.configure(fg_color=COLOR_BG)
        self.transient(parent)
        self.grab_set()
        self.tunnel_name = tunnel_name
        self.saved = False
        cur = appsettings.get_split(tunnel_name)

        ctk.CTkLabel(self, text="Split routing", font=(FONT_FAMILY, 16, "bold"),
                     anchor="w").pack(fill="x", padx=20, pady=(18, 2))
        ctk.CTkLabel(self, text=(
            "Off  —  use the config's AllowedIPs as-is.\n"
            "Exclude  —  full tunnel, but these go DIRECT (bypass the VPN).\n"
            "Include  —  ONLY these go through the VPN; everything else direct."),
            text_color=COLOR_MUTED, anchor="w", justify="left").pack(
            fill="x", padx=20, pady=(0, 10))

        self.mode_seg = ctk.CTkSegmentedButton(
            self, values=self.MODES, command=self._on_mode,
            fg_color=COLOR_PANEL, selected_color=COLOR_PRIMARY,
            selected_hover_color=COLOR_PRIMARY_HOVER)
        self.mode_seg.set(self._RMAP.get(cur.mode, "Off"))
        self.mode_seg.pack(fill="x", padx=20, pady=(0, 12))

        ctk.CTkLabel(self, text="IPs, CIDRs, or domains — one per line:",
                     text_color=COLOR_MUTED, anchor="w").pack(fill="x", padx=20)
        self.rules_box = ctk.CTkTextbox(self, font=(FONT_FAMILY, 12))
        self.rules_box.pack(fill="both", expand=True, padx=20, pady=(4, 10))
        if cur.rules:
            self.rules_box.insert("1.0", "\n".join(cur.rules))
        self._on_mode(self.mode_seg.get())

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=20, pady=(0, 16))
        ctk.CTkButton(btns, text="Save", width=110, fg_color=COLOR_PRIMARY,
                      hover_color=COLOR_PRIMARY_HOVER, command=self._save).pack(side="right")
        ctk.CTkButton(btns, text="Cancel", width=90, fg_color=COLOR_SEL,
                      hover_color=COLOR_HOVER, command=self.destroy).pack(
            side="right", padx=(0, 8))
        self.bind("<Escape>", lambda e: self.destroy())

    def _on_mode(self, val: str):
        self.rules_box.configure(
            state="disabled" if self._MAP.get(val) == "off" else "normal")

    def _save(self):
        mode = self._MAP.get(self.mode_seg.get(), "off")
        if mode != "off":
            raw = self.rules_box.get("1.0", "end")
            rules = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        else:
            rules = []
        appsettings.set_split(self.tunnel_name,
                              appsettings.SplitConfig(mode=mode, rules=rules))
        self.saved = True
        self.destroy()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Local WireGuard")
        self.geometry("960x600")
        self.minsize(360, 420)
        self.configure(fg_color=COLOR_BG)

        self.current: str | None = None
        self.activated_at: dict[str, float] = {}
        self.last_stats: dict[str, tuple[float, int, int]] = {}
        self.ping_thread: PingThread | None = None
        self.last_ping_ms: float = -1.0
        self.tunnel_buttons: dict[str, ctk.CTkButton] = {}
        self._busy: bool = False
        self._current_ping_host: str | None = None
        self._reconnect_monitor: AutoReconnectMonitor | None = None
        self._reconnect_status: str = ""

        # speed display (gated on poller sample time to kill phantom-zero spikes)
        self.last_rate: dict[str, tuple[float, float]] = {}
        # feature prefs + remembered UI state
        self._ui = appsettings.get_ui()
        # server geolocation
        self._country: str = ""
        self._geo_ip: str | None = None
        # collapsible sidebar animation state
        self._sidebar_width = 240
        self._sidebar_collapsed = self._ui.sidebar_collapsed
        self._side_visible = not self._sidebar_collapsed
        self._sidebar_cur = 0 if self._sidebar_collapsed else self._sidebar_width
        # DNS selector state
        self._dns_label_to_name: dict[str, str] = {}
        self._dns_ping: dict[str, float] = {}
        self._dns_test_thread: threading.Thread | None = None
        # tray
        self._tray = None
        self._tray_state = None

        ctk.set_appearance_mode("dark")
        self._build()
        self._refresh_dns_menu()
        if self._sidebar_collapsed:
            self.side.configure(width=1)
            self.side.grid_remove()
            self._side_visible = False
        self._setup_tray()

        self.poller = StatsPoller()
        self.poller.start()

        self.refresh_tunnels()
        self.after(300, self._tick)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.side = side = ctk.CTkFrame(self, fg_color="#232428", corner_radius=0,
                                        width=self._sidebar_width)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(1, weight=1)
        side.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(side, text="Tunnels", font=(FONT_FAMILY, 16, "bold"),
                     anchor="w").grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 6))

        self.list_frame = ctk.CTkScrollableFrame(side, fg_color="transparent")
        self.list_frame.grid(row=1, column=0, sticky="nsew", padx=6)

        btn_row = ctk.CTkFrame(side, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", padx=10, pady=(10, 4))
        btn_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(btn_row, text="+ Add", height=32,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=self.on_add).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(btn_row, text="Delete", height=32,
                      fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER,
                      command=self.on_delete).grid(row=0, column=1, sticky="ew", padx=(4, 0))

        ctk.CTkButton(side, text="⚙  Settings", height=32, anchor="w",
                      fg_color="transparent", hover_color=COLOR_HOVER,
                      text_color=COLOR_MUTED,
                      command=self.on_open_settings).grid(
            row=3, column=0, sticky="ew", padx=10, pady=(0, 10))

        self.detail = ctk.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0)
        self.detail.grid(row=0, column=1, sticky="nsew")
        self.detail.grid_columnconfigure(0, weight=1)

        self.empty_lbl = ctk.CTkLabel(self.detail, text="Select or add a tunnel",
                                       text_color=COLOR_MUTED, font=(FONT_FAMILY, 13))

        head = ctk.CTkFrame(self.detail, fg_color="transparent")
        head.grid_columnconfigure(1, weight=1)
        self.collapse_btn = ctk.CTkButton(
            head, text="☰", width=38, height=38, font=(FONT_FAMILY, 18),
            fg_color=COLOR_PANEL, hover_color=COLOR_HOVER,
            command=self.toggle_sidebar)
        self.collapse_btn.grid(row=0, column=0, rowspan=2, sticky="w", padx=(0, 12))
        self.name_lbl = ctk.CTkLabel(head, text="—", font=(FONT_FAMILY, 20, "bold"), anchor="w")
        self.name_lbl.grid(row=0, column=1, sticky="ew")
        self.status_lbl = ctk.CTkLabel(head, text="Inactive", text_color=COLOR_MUTED,
                                        font=(FONT_FAMILY, 12, "bold"), anchor="e")
        self.status_lbl.grid(row=0, column=2, sticky="e")
        self.country_lbl = ctk.CTkLabel(head, text="", text_color=COLOR_MUTED,
                                         font=(FONT_FAMILY, 12), anchor="w")
        self.country_lbl.grid(row=1, column=1, sticky="w")

        btns = ctk.CTkFrame(self.detail, fg_color="transparent")
        self.toggle_btn = ctk.CTkButton(btns, text="Connect", width=140, height=36,
                                         fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
                                         font=(FONT_FAMILY, 12, "bold"),
                                         command=self.on_toggle)
        self.toggle_btn.pack(side="left", padx=(0, 8))
        self.edit_btn = ctk.CTkButton(btns, text="Edit", width=100, height=36,
                                       fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                                       command=self.on_edit)
        self.edit_btn.pack(side="left")
        self.split_btn = ctk.CTkButton(btns, text="Split", width=90, height=36,
                                        fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                                        command=self.on_split)
        self.split_btn.pack(side="left", padx=(8, 0))

        dns_bar = ctk.CTkFrame(self.detail, fg_color=COLOR_PANEL, corner_radius=10)
        dns_bar.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(dns_bar, text="DNS", text_color=COLOR_MUTED,
                     font=(FONT_FAMILY, 10, "bold"), width=44, anchor="w").grid(
            row=0, column=0, sticky="w", padx=(14, 6), pady=10)
        self.dns_var = ctk.StringVar(value="Default")
        self.dns_menu = ctk.CTkOptionMenu(
            dns_bar, variable=self.dns_var, values=["Default"],
            command=self._on_dns_select, width=220,
            fg_color=COLOR_SEL, button_color=COLOR_SEL,
            button_hover_color=COLOR_HOVER, dropdown_fg_color=COLOR_PANEL)
        self.dns_menu.grid(row=0, column=1, sticky="w", pady=10)
        self.dns_test_btn = ctk.CTkButton(
            dns_bar, text="Test ping", width=90, height=28,
            fg_color=COLOR_SEL, hover_color=COLOR_HOVER, command=self._on_dns_test)
        self.dns_test_btn.grid(row=0, column=2, padx=6, pady=10)
        ctk.CTkButton(dns_bar, text="Manage", width=80, height=28,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=self._open_dns_manager).grid(row=0, column=3, padx=(0, 12), pady=10)
        self.dns_bar = dns_bar

        card = ctk.CTkFrame(self.detail, fg_color=COLOR_PANEL, corner_radius=10)
        card.grid_columnconfigure(1, weight=1)

        self.stats_widgets: dict[str, ctk.CTkLabel] = {}
        rows = [
            ("ping", "Ping"), ("uptime", "Uptime"),
            ("down", "Download"), ("up", "Upload"),
            ("rx", "RX total"), ("tx", "TX total"),
            ("ep", "Endpoint"),
        ]
        for i, (key, label) in enumerate(rows):
            ctk.CTkLabel(card, text=label.upper(), text_color=COLOR_MUTED,
                         font=(FONT_FAMILY, 10, "bold"), anchor="w").grid(
                row=i, column=0, sticky="w", padx=16, pady=6
            )
            v = ctk.CTkLabel(card, text="—", font=(FONT_FAMILY, 13), anchor="w")
            v.grid(row=i, column=1, sticky="w", padx=8, pady=6)
            self.stats_widgets[key] = v

        self.detail_widgets = (head, btns, dns_bar, card)
        self._show_empty()

    def _show_empty(self):
        for w in self.detail_widgets:
            w.grid_forget()
        self.empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

    def _show_detail(self):
        self.empty_lbl.place_forget()
        head, btns, dns_bar, card = self.detail_widgets
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 6))
        btns.grid(row=1, column=0, sticky="w", padx=24, pady=(0, 14))
        if self._ui.dns_changer_enabled:
            dns_bar.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 14))
        else:
            dns_bar.grid_forget()
        card.grid(row=3, column=0, sticky="new", padx=24, pady=(0, 24))

    # --- tunnel list ---
    def refresh_tunnels(self, keep: str | None = None):
        for w in self.list_frame.winfo_children():
            w.destroy()
        self.tunnel_buttons.clear()
        tunnels = wgapi.list_tunnels()
        for t in tunnels:
            name = t["name"]
            btn = ctk.CTkButton(
                self.list_frame, text=name, height=34, anchor="w",
                fg_color="transparent", hover_color=COLOR_HOVER,
                text_color=COLOR_TEXT,
                command=lambda n=name: self._select(n),
            )
            btn.pack(fill="x", padx=2, pady=2)
            self.tunnel_buttons[name] = btn
        if keep and keep in self.tunnel_buttons:
            self._select(keep)
        elif self.current and self.current in self.tunnel_buttons:
            self._select(self.current)
        elif tunnels:
            self._select(tunnels[0]["name"])
        else:
            self.current = None
            self.poller.set_tunnel(None)
            self._show_empty()

    def _select(self, name: str):
        self.current = name
        for n, btn in self.tunnel_buttons.items():
            btn.configure(fg_color=COLOR_SEL if n == name else "transparent")
        self.name_lbl.configure(text=name)
        self._show_detail()
        self._stop_ping()
        # selecting a different tunnel: drop stale geolocation + DNS pick view
        self._country = ""
        self._geo_ip = None
        self.country_lbl.configure(text="")
        self._refresh_dns_menu()
        self.poller.set_tunnel(name)
        # Reset display until poller fills in
        for k in ("ping", "uptime", "down", "up", "rx", "tx", "ep"):
            self.stats_widgets[k].configure(text="…")
        self.status_lbl.configure(text="…", text_color=COLOR_MUTED)

    # --- actions ---
    def on_add(self):
        d = TunnelDialog(self)
        self.wait_window(d)
        if not d.result: return
        name, conf = d.result
        self._run_async(
            lambda: wgapi.add_tunnel(name, conf),
            lambda res: self._after_add(name, res),
        )

    def _after_add(self, name, res):
        ok, msg = res
        if not ok:
            messagebox.showerror("Add failed", msg, parent=self)
            return
        self.refresh_tunnels(keep=name)

    def on_edit(self):
        if not self.current: return
        cfg = wgapi.read_tunnel_config(self.current) or ""
        if cfg.startswith("[Encrypted"):
            messagebox.showinfo("Cannot edit", cfg, parent=self)
            return
        d = TunnelDialog(self, name=self.current, config=cfg, edit_mode=True)
        self.wait_window(d)
        if not d.result: return
        _, new_cfg = d.result
        name = self.current
        self._run_async(
            lambda: wgapi.update_tunnel(name, new_cfg),
            lambda res: self._show_err_if_fail(res, "Save failed"),
        )

    def on_delete(self):
        if not self.current: return
        if not messagebox.askyesno("Delete tunnel",
                                    f"Delete tunnel '{self.current}'?", parent=self):
            return
        name = self.current
        self._run_async(
            lambda: wgapi.delete_tunnel(name),
            lambda res: self._after_delete(name, res),
        )

    def _after_delete(self, name, res):
        ok, msg = res
        if not ok:
            messagebox.showerror("Delete failed", msg, parent=self)
            return
        if self.current == name:
            self.current = None
        self.refresh_tunnels()

    def on_split(self):
        if not self.current:
            return
        d = SplitConfigDialog(self, self.current)
        self.wait_window(d)
        if d.saved and wgapi.is_active(self.current):
            messagebox.showinfo(
                "Split routing",
                "Saved. Reconnect this tunnel to apply the new routing.",
                parent=self)

    def on_open_settings(self):
        d = SettingsDialog(self, tunnel_name=self.current)
        self.wait_window(d)
        # Auto-reconnect monitor reads settings live, so no action needed there.
        # Reload feature prefs and re-grid in case the user toggled DNS/country.
        self._ui = appsettings.get_ui()
        if self.current:
            self._show_detail()
        self._refresh_dns_menu()

    def on_toggle(self):
        if not self.current or self._busy: return
        name = self.current
        self._set_busy(True)
        self.toggle_btn.configure(text="…")
        threading.Thread(target=self._toggle_worker, args=(name,), daemon=True).start()

    def _toggle_worker(self, name: str):
        try:
            if wgapi.is_active(name):
                self._stop_reconnect_monitor()
                ok, msg = wgapi.deactivate(name)
            else:
                active = wgapi.get_active_tunnel()
                if active and active != name:
                    self._stop_reconnect_monitor()
                    wgapi.deactivate(active)
                ok, msg = wgapi.activate(name)
                if ok:
                    self.activated_at[name] = time.time()
                    self._start_reconnect_monitor(name)
        except Exception as e:
            ok, msg = False, str(e)
        self.after(0, lambda: self._after_toggle(ok, msg))

    def _after_toggle(self, ok: bool, msg: str):
        self._set_busy(False)
        if not ok:
            messagebox.showerror("Operation failed", msg, parent=self)
        self.poller.poke()

    def _start_reconnect_monitor(self, name: str):
        self._stop_reconnect_monitor()
        self._reconnect_status = ""
        ar = appsettings.get_auto_reconnect_for(name)
        if not ar.enabled:
            return
        self._reconnect_monitor = AutoReconnectMonitor(
            name, callback=self._on_reconnect_event,
        )
        self._reconnect_monitor.start()

    def _stop_reconnect_monitor(self):
        if self._reconnect_monitor:
            self._reconnect_monitor.stop()
            self._reconnect_monitor = None

    def _on_reconnect_event(self, evt: str, info: str):
        # Called from monitor thread — marshal to main loop
        self.after(0, lambda: self._handle_reconnect_event(evt, info))

    def _handle_reconnect_event(self, evt: str, info: str):
        if evt == "reconnect_triggered":
            self._reconnect_status = f"Slow link — reconnecting ({info})"
        elif evt == "reconnect_done":
            self._reconnect_status = "Reconnected"
            # Reset activated_at so uptime resets
            if self.current:
                self.activated_at[self.current] = time.time()
        elif evt == "reconnect_failed":
            self._reconnect_status = f"Reconnect failed: {info}"

    def _run_async(self, work, done):
        if self._busy: return
        self._set_busy(True)
        def run():
            try:
                res = work()
            except Exception as e:
                res = (False, str(e))
            self.after(0, lambda: (self._set_busy(False), done(res)))
        threading.Thread(target=run, daemon=True).start()

    def _set_busy(self, b: bool):
        self._busy = b
        state = "disabled" if b else "normal"
        self.toggle_btn.configure(state=state)
        self.edit_btn.configure(state=state)

    def _show_err_if_fail(self, res, title):
        ok, msg = res
        if not ok:
            messagebox.showerror(title, msg, parent=self)

    # --- collapsible sidebar (ease-out, ~100ms) ---
    def toggle_sidebar(self):
        self._sidebar_collapsed = not self._sidebar_collapsed
        appsettings.set_sidebar_collapsed(self._sidebar_collapsed)
        self._anim_from = self._sidebar_cur
        self._anim_to = 0 if self._sidebar_collapsed else self._sidebar_width
        self._anim_step = 0
        self._animate_sidebar()

    def _animate_sidebar(self):
        frames = 10
        self._anim_step += 1
        t = min(1.0, self._anim_step / frames)
        e = 1 - (1 - t) ** 3  # ease-out cubic
        cur = int(self._anim_from + (self._anim_to - self._anim_from) * e)
        self._sidebar_cur = cur
        if cur <= 0:
            if self._side_visible:
                self.side.grid_remove()
                self._side_visible = False
        else:
            if not self._side_visible:
                self.side.grid()
                self._side_visible = True
            self.side.configure(width=max(1, cur))
        if t < 1.0:
            self.after(10, self._animate_sidebar)
        elif self._anim_to <= 0 and self._side_visible:
            self.side.grid_remove()
            self._side_visible = False

    # --- DNS changer ---
    def _refresh_dns_menu(self):
        entries = appsettings.get_enabled_dns()
        if self._dns_ping:
            entries.sort(key=lambda e: self._dns_ping.get(e.name, 1e9)
                         if self._dns_ping.get(e.name, -1) >= 0 else 1e9)
        self._dns_label_to_name = {"Default": ""}
        values = ["Default"]
        for e in entries:
            label = e.name
            ms = self._dns_ping.get(e.name)
            if ms is not None:
                label = f"{e.name}  ·  {int(ms)} ms" if ms >= 0 else f"{e.name}  ·  —"
            self._dns_label_to_name[label] = e.name
            values.append(label)
        self.dns_menu.configure(values=values)
        sel_name = appsettings.get_selected_dns(self.current) if self.current else ""
        target = "Default"
        for lbl, nm in self._dns_label_to_name.items():
            if nm == sel_name:
                target = lbl
                break
        self.dns_var.set(target)

    def _on_dns_select(self, label: str):
        name = self._dns_label_to_name.get(label, "")
        if self.current:
            appsettings.set_selected_dns(self.current, name)
        self._apply_dns_now(name)

    def _apply_dns_now(self, dns_name: str):
        if not self.current or not wgapi.is_active(self.current):
            return  # DNS is applied to the live adapter — connect first
        servers: list[str] = []
        if dns_name:
            for e in appsettings.get_dns_catalog():
                if e.name == dns_name:
                    servers = e.servers
                    break
        name = self.current
        def work():
            ok, msg = wgapi.set_dns(name, servers)
            if not ok:
                self.after(0, lambda: messagebox.showwarning(
                    "DNS", f"Could not set DNS: {msg}", parent=self))
        threading.Thread(target=work, daemon=True).start()

    def _on_dns_test(self):
        if self._dns_test_thread and self._dns_test_thread.is_alive():
            return
        entries = [e for e in appsettings.get_enabled_dns() if e.servers]
        if not entries:
            return
        self.dns_test_btn.configure(text="Testing…", state="disabled")
        def work():
            import concurrent.futures as cf
            with cf.ThreadPoolExecutor(max_workers=10) as ex:
                futs = {ex.submit(ping_ms, e.servers[0]): e.name for e in entries}
                for fut in cf.as_completed(futs):
                    nm = futs[fut]
                    try:
                        ms = fut.result()
                    except Exception:
                        ms = -1.0
                    self.after(0, lambda n=nm, m=ms: self._dns_test_one(n, m))
            self.after(0, self._dns_test_done)
        self._dns_test_thread = threading.Thread(target=work, daemon=True)
        self._dns_test_thread.start()

    def _dns_test_one(self, name: str, ms: float):
        self._dns_ping[name] = ms
        self._refresh_dns_menu()

    def _dns_test_done(self):
        self.dns_test_btn.configure(text="Test ping", state="normal")
        self._refresh_dns_menu()

    def _open_dns_manager(self):
        d = DnsManagerDialog(self)
        self.wait_window(d)
        if d.changed:
            self._dns_ping.clear()
            self._refresh_dns_menu()

    # --- server geolocation ---
    def _maybe_lookup_geo(self, ip: str):
        if ip == self._geo_ip:
            return
        self._geo_ip = ip
        self._country = ""
        def work():
            name, code = lookup_country(ip)
            txt = f"{name} ({code})" if name and code else (code or name or "")
            self.after(0, lambda: self._set_country(ip, txt))
        threading.Thread(target=work, daemon=True).start()

    def _set_country(self, ip: str, txt: str):
        if ip == self._geo_ip:
            self._country = txt

    # --- system tray ---
    def _setup_tray(self):
        if not self._ui.tray_enabled:
            return
        try:
            import pystray
            menu = pystray.Menu(
                pystray.MenuItem("Show / Hide", self._tray_toggle_window, default=True),
                pystray.MenuItem("Connect / Disconnect", self._tray_toggle_conn),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit", self._tray_quit),
            )
            self._tray = pystray.Icon(
                "localwg", build_tray_image(False, False, False),
                "Local WireGuard", menu)
            self._tray.run_detached()
        except Exception:
            self._tray = None

    def _update_tray(self, active: bool, drx: float, dtx: float):
        if not self._tray:
            return
        title = "Local WireGuard"
        if self.current:
            title = f"{self.current} — {'Active' if active else 'Inactive'}"
            if active:
                title += f"\n↑ {fmt_rate(dtx)}   ↓ {fmt_rate(drx)}"
                if self._country:
                    title += f"\n{self._country}"
        state = (active, active and dtx > 256, active and drx > 256)
        try:
            self._tray.title = title
            if state != self._tray_state:
                self._tray.icon = build_tray_image(*state)
                self._tray_state = state
        except Exception:
            pass

    def _tray_toggle_window(self, icon=None, item=None):
        self.after(0, self._do_toggle_window)

    def _do_toggle_window(self):
        try:
            if self.state() in ("withdrawn", "iconic"):
                self.deiconify()
                self.lift()
                self.focus_force()
            else:
                self.withdraw()
        except Exception:
            pass

    def _tray_toggle_conn(self, icon=None, item=None):
        self.after(0, self.on_toggle)

    def _tray_quit(self, icon=None, item=None):
        self.after(0, self._on_close)

    # --- tick (reads cached snapshot from poller) ---
    def _tick(self):
        try:
            self._apply_snapshot()
        finally:
            self.after(500, self._tick)

    def _apply_snapshot(self):
        if not self.current:
            return
        snap = self.poller.get_snapshot()
        if snap["tunnel"] != self.current:
            return
        active = snap["active"]
        stats = snap["stats"]

        if not self._busy:
            if active:
                txt = "● Active"
                if self._reconnect_status:
                    txt = f"● Active  ·  {self._reconnect_status}"
                self.status_lbl.configure(text=txt, text_color=COLOR_OK)
                self.toggle_btn.configure(text="Disconnect",
                                           fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER)
            else:
                self.status_lbl.configure(text="Inactive", text_color=COLOR_MUTED)
                self.toggle_btn.configure(text="Connect",
                                           fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER)
                self._reconnect_status = ""

        # DNS controls are usable only while connected (DNS is applied to the
        # live adapter). Reflect that here.
        if self._ui.dns_changer_enabled:
            testing = bool(self._dns_test_thread and self._dns_test_thread.is_alive())
            self.dns_menu.configure(state="normal" if active else "disabled")
            self.dns_test_btn.configure(
                state="normal" if (active and not testing) else "disabled")

        drx = dtx = 0.0
        if active and stats:
            rx = stats["rx_bytes"]; tx = stats["tx_bytes"]
            ts = snap["ts"]
            now = time.time()
            prev = self.last_stats.get(self.current)
            # Recompute the rate ONLY when the poller produced a fresh sample.
            # The UI ticks at 500ms but the poller samples at 1s, so otherwise
            # half the ticks see an unchanged rx/tx and would show a phantom 0.
            if prev is None:
                self.last_stats[self.current] = (ts, rx, tx)
                self.last_rate[self.current] = (0.0, 0.0)
            elif ts > prev[0]:
                dt = max(ts - prev[0], 0.001)
                self.last_rate[self.current] = (
                    max(rx - prev[1], 0) / dt, max(tx - prev[2], 0) / dt)
                self.last_stats[self.current] = (ts, rx, tx)
            drx, dtx = self.last_rate.get(self.current, (0.0, 0.0))
            self.stats_widgets["down"].configure(text=fmt_rate(drx))
            self.stats_widgets["up"].configure(text=fmt_rate(dtx))
            self.stats_widgets["rx"].configure(text=fmt_bytes(rx))
            self.stats_widgets["tx"].configure(text=fmt_bytes(tx))
            self.stats_widgets["ep"].configure(text=stats["endpoint"] or "—")
            if self.current not in self.activated_at:
                self.activated_at[self.current] = now
            self.stats_widgets["uptime"].configure(
                text=fmt_duration(int(now - self.activated_at[self.current])))

            # On the first active tick for this tunnel, apply its saved DNS pick.
            if getattr(self, "_dns_applied_for", None) != self.current:
                self._dns_applied_for = self.current
                self._apply_dns_now(appsettings.get_selected_dns(self.current))

            host = None
            if (wgapi.CONF_DIR / f"{self.current}.conf").exists():
                host = wgapi.parse_endpoint_host(wgapi.read_tunnel_config(self.current) or "")
            ep_ip = (stats["endpoint"] or "").rsplit(":", 1)[0].strip("[]")
            if not host and ep_ip:
                host = ep_ip
            if host and host != self._current_ping_host:
                self._stop_ping()
                self._start_ping(host)
            elif not host:
                self._stop_ping()
            if self.last_ping_ms >= 0:
                self.stats_widgets["ping"].configure(text=f"{self.last_ping_ms:.0f} ms")
            elif self._current_ping_host:
                self.stats_widgets["ping"].configure(text="…")
            else:
                self.stats_widgets["ping"].configure(text="—")

            # Server geolocation (country name + code, text only).
            if self._ui.show_country and ep_ip:
                self._maybe_lookup_geo(ep_ip)
            self.country_lbl.configure(
                text=self._country if (self._ui.show_country and self._country) else "")
        else:
            self._stop_ping()
            for k in ("ping", "uptime", "down", "up", "rx", "tx", "ep"):
                self.stats_widgets[k].configure(text="—")
            self.last_stats.pop(self.current, None)
            self.last_rate.pop(self.current, None)
            self.activated_at.pop(self.current, None)
            self.country_lbl.configure(text="")
            if getattr(self, "_dns_applied_for", None) == self.current:
                self._dns_applied_for = None

        self._update_tray(active, drx, dtx)

    # --- ping ---
    def _start_ping(self, host: str):
        self.last_ping_ms = -1.0
        self._current_ping_host = host
        self.ping_thread = PingThread(host, self._on_ping)
        self.ping_thread.start()

    def _stop_ping(self):
        if self.ping_thread:
            self.ping_thread.stop()
            self.ping_thread = None
        self._current_ping_host = None
        self.last_ping_ms = -1.0

    def _on_ping(self, host: str, ms: float):
        if host == self._current_ping_host:
            self.last_ping_ms = ms

    def _on_close(self):
        self._stop_ping()
        self._stop_reconnect_monitor()
        self.poller.stop()
        if self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass
            self._tray = None
        self.destroy()


def main():
    _apply_theme()
    if not wgapi.WG_EXE.exists():
        try:
            import tkinter as tk
            r = tk.Tk(); r.withdraw()
            messagebox.showerror("WireGuard not found", f"wireguard.exe not found at:\n{wgapi.WG_EXE}")
        except Exception:
            print(f"wireguard.exe not found at {wgapi.WG_EXE}", file=sys.stderr)
        return 1
    if not wgapi.is_admin():
        script = str(Path(__file__).resolve())
        cwd = str(Path(__file__).resolve().parent)
        ps_cmd = (
            f'Start-Process cmd '
            f'-ArgumentList \'/c\',\'cd /d \"\"{cwd}\"\" && python \"\"{script}\"\"\' '
            f'-Verb RunAs'
        )
        try:
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=30)
        except Exception as e:
            print(f"Admin elevation failed: {e}", file=sys.stderr)
            return 1
        return 0
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
