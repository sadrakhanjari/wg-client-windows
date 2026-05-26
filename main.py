import os
import sys
import json
import time
import socket
import struct
import ctypes
import threading
import subprocess
import urllib.request
from pathlib import Path
import tkinter as tk
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


def ping_stats(host: str, count: int = 5, timeout_ms: int = 1000) -> tuple[float, float]:
    """Run `count` ICMP pings; return (avg_latency_ms, loss_pct).

    avg is -1 if every probe was lost / the host didn't resolve. Loss is derived
    from how many replies we actually saw (locale-proof — we count `time=` reply
    lines instead of parsing the localized 'Lost = N' summary)."""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return -1.0, 100.0
    try:
        r = subprocess.run(
            ["ping", "-n", str(count), "-w", str(timeout_ms), ip],
            capture_output=True, text=True,
            timeout=count * (timeout_ms / 1000.0) + 5,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        return -1.0, 100.0
    times: list[float] = []
    for line in r.stdout.splitlines():
        low = line.lower()
        if "time=" in low or "time<" in low:
            seg = low.split("time")[1][1:]
            num = ""
            for ch in seg:
                if ch.isdigit() or ch == ".":
                    num += ch
                elif num:
                    break
            if num:
                times.append(float(num))
    recv = len(times)
    loss = 100.0 * (count - recv) / count if count else 100.0
    avg = sum(times) / len(times) if times else -1.0
    return avg, loss


_DNS_TEST_NAMES = ("example.com", "wikipedia.org", "github.com", "cloudflare.com")


def dns_query_ms(server: str, qname: str = "example.com",
                 timeout: float = 1.5) -> float:
    """Send one A-record DNS query over UDP/53 to `server`; return RTT in ms,
    or -1 on timeout/refusal. Pure socket — no external resolver libs."""
    tid = os.urandom(2)
    header = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname_bytes = b"".join(
        bytes([len(p)]) + p.encode("idna" if any(ord(c) > 127 for c in p) else "ascii")
        for p in qname.split(".") if p) + b"\x00"
    packet = header + qname_bytes + struct.pack(">HH", 1, 1)  # type A, class IN
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.perf_counter()
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(1500)
        if len(data) < 4 or data[:2] != tid:
            return -1.0
        return (time.perf_counter() - t0) * 1000.0
    except Exception:
        return -1.0
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_dns(server: str, queries: int = 4) -> dict:
    """Full health probe of one resolver: ICMP latency + loss, plus real DNS
    query RTT + DNS loss. Produces a single `score` (lower = better) used to
    rank servers, and `ok` if it answers DNS at all.

    score = dns_rtt + dns_loss%*5   (DNS that actually resolves is what matters);
    if DNS never answers we fall back to ICMP with a heavy penalty so a pingable-
    but-not-resolving box always sorts below a working resolver."""
    ping_avg, ping_loss = ping_stats(server, count=5)
    rtts: list[float] = []
    for i in range(queries):
        ms = dns_query_ms(server, _DNS_TEST_NAMES[i % len(_DNS_TEST_NAMES)])
        if ms >= 0:
            rtts.append(ms)
    dns_recv = len(rtts)
    dns_loss = 100.0 * (queries - dns_recv) / queries if queries else 100.0
    dns_rtt = sum(rtts) / len(rtts) if rtts else -1.0
    ok = dns_rtt >= 0
    if ok:
        score = dns_rtt + dns_loss * 5.0
    elif ping_avg >= 0:
        score = 2000.0 + ping_avg + ping_loss * 5.0
    else:
        score = float("inf")
    return {
        "server": server, "ok": ok, "score": score,
        "ping_ms": ping_avg, "ping_loss": ping_loss,
        "dns_ms": dns_rtt, "dns_loss": dns_loss,
    }


def score_color(score: float) -> str:
    """Quality color for a probe score (lower = better)."""
    if score == float("inf"):
        return COLOR_DANGER
    if score < 60:
        return "#22c55e"     # excellent
    if score < 140:
        return "#84cc16"     # good
    if score < 300:
        return "#f59e0b"     # ok
    return "#f97316"         # poor


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


HUD_BG = "#0d0e11"


class OverlayHUD:
    """Borderless, always-on-top, click-through HUD pinned to a screen corner,
    showing live download/upload/ping (+ optional mini speed graph)."""

    def __init__(self, master, prefs, value_provider):
        self.master = master
        self.prefs = prefs
        self.provider = value_provider     # () -> {active, down, up, ping}
        self.win: tk.Toplevel | None = None
        self._after = None
        self._down_hist: list[float] = []
        self._up_hist: list[float] = []
        self._build()

    def _build(self):
        p = self.prefs
        self.win = tk.Toplevel(self.master)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        try:
            self.win.attributes("-alpha", p.opacity)
        except Exception:
            pass
        self.win.configure(bg=HUD_BG)
        self.frame = tk.Frame(self.win, bg=HUD_BG)
        self.frame.pack(fill="both", expand=True, padx=p.padding, pady=p.padding)
        self.labels = {}
        for key in ("down", "up", "ping"):
            self.labels[key] = tk.Label(
                self.frame, text="", bg=HUD_BG, fg=p.color, width=13,
                font=(p.font_family, p.font_size, "bold"), anchor="w", justify="left")
        self.canvas = tk.Canvas(self.frame, bg=HUD_BG, highlightthickness=0,
                                height=42, width=p.font_size * 11)
        self._layout_items()
        self.win.update_idletasks()
        self._reposition()
        self._make_clickthrough()
        self._tick()

    def _layout_items(self):
        for w in list(self.labels.values()) + [self.canvas]:
            w.pack_forget()
        p = self.prefs
        order = []
        if p.show_download:
            order.append("down")
        if p.show_upload:
            order.append("up")
        if p.show_ping:
            order.append("ping")
        for i, key in enumerate(order):
            self.labels[key].pack(anchor="w", pady=(0 if i == 0 else p.spacing, 0))
        if p.show_graph:
            self.canvas.pack(anchor="w", pady=(p.spacing if order else 0, 0))

    def _make_clickthrough(self):
        try:
            import ctypes
            GWL_EXSTYLE = -20
            WS_EX_LAYERED = 0x80000
            WS_EX_TRANSPARENT = 0x20
            WS_EX_TOOLWINDOW = 0x80
            LWA_ALPHA = 0x2
            u = ctypes.windll.user32
            hwnd = self.win.winfo_id()
            cur = u.GetWindowLongW(hwnd, GWL_EXSTYLE)
            u.SetWindowLongW(
                hwnd, GWL_EXSTYLE,
                cur | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW)
            # Changing the ex-style on a WS_EX_LAYERED window wipes the alpha
            # Tk set via -alpha; without re-asserting it the window has no valid
            # layered attributes and DWM paints it as a solid black box. Set it
            # again so the HUD actually composites onto the screen.
            alpha = max(0, min(255, int(self.prefs.opacity * 255)))
            u.SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA)
        except Exception:
            pass

    def _reposition(self):
        if not self.win:
            return
        self.win.update_idletasks()
        w = self.win.winfo_reqwidth()
        h = self.win.winfo_reqheight()
        sw = self.win.winfo_screenwidth()
        sh = self.win.winfo_screenheight()
        m = self.prefs.margin
        pos = self.prefs.position
        x = m if "left" in pos else max(0, sw - w - m)
        y = m if "top" in pos else max(0, sh - h - m)
        self.win.geometry(f"+{x}+{y}")

    def _push_graph(self, down, up):
        n = 60
        self._down_hist.append(down)
        self._up_hist.append(up)
        self._down_hist = self._down_hist[-n:]
        self._up_hist = self._up_hist[-n:]

    def _draw_graph(self):
        c = self.canvas
        c.delete("all")
        W = c.winfo_width() or c.winfo_reqwidth()
        H = c.winfo_height() or 42
        mx = max(self._down_hist + self._up_hist + [1.0])

        def line(hist, col):
            if len(hist) < 2:
                return
            step = W / max(1, len(hist) - 1)
            pts = []
            for i, val in enumerate(hist):
                pts += [i * step, H - (val / mx) * (H - 2) - 1]
            c.create_line(*pts, fill=col, width=1)

        line(self._down_hist, self.prefs.color)
        line(self._up_hist, "#7a7d85")

    def _tick(self):
        if not self.win:
            return
        try:
            v = self.provider() or {}
            active = bool(v.get("active"))
            down, up, ping = v.get("down", 0.0), v.get("up", 0.0), v.get("ping", -1.0)
            self.labels["down"].configure(text=f"↓ {fmt_rate(down)}" if active else "↓  —")
            self.labels["up"].configure(text=f"↑ {fmt_rate(up)}" if active else "↑  —")
            self.labels["ping"].configure(
                text=f"⏱ {ping:.0f} ms" if (active and ping >= 0) else "⏱  —")
            if self.prefs.show_graph:
                self._push_graph(down if active else 0.0, up if active else 0.0)
                self._draw_graph()
            # keep it glued to the top of the z-order and pinned to its corner
            self.win.attributes("-topmost", True)
            self._reposition()
        except Exception:
            pass
        self._after = self.master.after(self.prefs.refresh_ms, self._tick)

    def destroy(self):
        if self._after:
            try:
                self.master.after_cancel(self._after)
            except Exception:
                pass
            self._after = None
        if self.win:
            try:
                self.win.destroy()
            except Exception:
                pass
            self.win = None


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
        rowf = ctk.CTkFrame(self, fg_color="transparent")
        rowf.pack(anchor="w", padx=24, pady=(8, 0))
        ctk.CTkButton(rowf, text="Manage DNS list…", width=160, height=30,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=lambda: DnsManagerDialog(self)).pack(side="left")
        ctk.CTkButton(rowf, text="Overlay (HUD)…", width=140, height=30,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=lambda: OverlayDialog(self, self.master)).pack(
            side="left", padx=(8, 0))

        # --- Appearance (applies on restart) ---
        ctk.CTkLabel(self, text="Appearance  (applies on restart)",
                     font=(FONT_FAMILY, 16, "bold"), anchor="w").pack(
            fill="x", padx=24, pady=(16, 4))
        appr = ctk.CTkFrame(self, fg_color="transparent")
        appr.pack(fill="x", padx=24)
        appr.grid_columnconfigure(1, weight=1)
        self._accent_map = {n: c for n, c in appsettings.ACCENT_CHOICES}
        cur_accent = next((n for n, c in appsettings.ACCENT_CHOICES if c == ui.accent),
                          appsettings.ACCENT_CHOICES[0][0])

        ctk.CTkLabel(appr, text="Font").grid(row=0, column=0, sticky="w", pady=6)
        self.font_var = ctk.StringVar(value=ui.font_family)
        ctk.CTkOptionMenu(appr, variable=self.font_var,
                          values=appsettings.FONT_CHOICES, width=200,
                          command=self._preview, fg_color=COLOR_SEL,
                          button_color=COLOR_SEL, button_hover_color=COLOR_HOVER,
                          dropdown_fg_color=COLOR_PANEL).grid(
            row=0, column=1, sticky="ew", padx=8, pady=6)
        ctk.CTkLabel(appr, text="Accent color").grid(row=1, column=0, sticky="w", pady=6)
        self.accent_var = ctk.StringVar(value=cur_accent)
        ctk.CTkOptionMenu(appr, variable=self.accent_var,
                          values=[n for n, _ in appsettings.ACCENT_CHOICES], width=200,
                          command=self._preview, fg_color=COLOR_SEL,
                          button_color=COLOR_SEL, button_hover_color=COLOR_HOVER,
                          dropdown_fg_color=COLOR_PANEL).grid(
            row=1, column=1, sticky="ew", padx=8, pady=6)
        self.accent_swatch = ctk.CTkLabel(appr, text="", width=28, height=22,
                                          corner_radius=5, fg_color=ui.accent)
        self.accent_swatch.grid(row=1, column=2, padx=(2, 0))

        # live preview of the chosen font + color
        prev = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=8)
        prev.pack(fill="x", padx=24, pady=(8, 0))
        ctk.CTkLabel(prev, text="Preview", text_color=COLOR_MUTED,
                     font=(FONT_FAMILY, 10, "bold")).pack(anchor="w", padx=12, pady=(8, 0))
        self.font_sample = ctk.CTkLabel(
            prev, text="The quick brown fox  AaBbCc 0123  •  نمونه فارسی",
            font=(ui.font_family, 16, "bold"), text_color=ui.accent, anchor="w")
        self.font_sample.pack(fill="x", padx=12, pady=(2, 10))

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

    def _preview(self, _=None):
        col = self._accent_map.get(self.accent_var.get(), COLOR_PRIMARY)
        try:
            self.font_sample.configure(font=(self.font_var.get(), 16, "bold"),
                                       text_color=col)
            self.accent_swatch.configure(fg_color=col)
        except Exception:
            pass


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


class DnsTestDialog(ctk.CTkToplevel):
    """Probe every enabled resolver (latency, packet loss, DNS query RTT/loss),
    rank best-first, and let the user pick one to use."""

    def __init__(self, parent, entries):
        super().__init__(parent)
        self.title("DNS test")
        self.geometry("680x560")
        self.configure(fg_color=COLOR_BG)
        self.transient(parent)
        self.grab_set()
        self.entries = entries
        self.results: list[dict] = []     # filled when probing finishes
        self.chosen: str | None = None    # name the user clicked "Use" on
        self._rows: dict[str, dict] = {}  # name -> widgets
        self._done = 0

        ctk.CTkLabel(self, text="DNS test", font=(FONT_FAMILY, 16, "bold"),
                     anchor="w").pack(fill="x", padx=20, pady=(18, 2))
        self.subtitle = ctk.CTkLabel(
            self, text=f"Probing {len(entries)} servers — ping loss, latency & "
                       f"DNS query time. Best first.",
            text_color=COLOR_MUTED, anchor="w")
        self.subtitle.pack(fill="x", padx=20, pady=(0, 8))

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=22)
        cols = [("Server", 150, "w"), ("DNS", 95, "e"), ("DNS loss", 80, "e"),
                ("Ping", 80, "e"), ("Loss", 70, "e"), ("Score", 70, "e"),
                ("", 60, "e")]
        for txt, w, anchor in cols:
            ctk.CTkLabel(header, text=txt, width=w, anchor=anchor,
                         text_color=COLOR_MUTED,
                         font=(FONT_FAMILY, 10, "bold")).pack(side="left", padx=2)

        self.scroll = ctk.CTkScrollableFrame(self, fg_color=COLOR_PANEL)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=(4, 8))
        for e in entries:
            self._make_row(e)

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=20, pady=(0, 16))
        self.retest_btn = ctk.CTkButton(btns, text="Re-test", width=100,
                                        fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                                        command=self._start, state="disabled")
        self.retest_btn.pack(side="left")
        ctk.CTkButton(btns, text="Close", width=90, fg_color=COLOR_SEL,
                      hover_color=COLOR_HOVER, command=self.destroy).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())
        self._start()

    def _make_row(self, entry):
        row = ctk.CTkFrame(self.scroll, fg_color="transparent")
        row.pack(fill="x", pady=2)
        server = entry.servers[0]
        name_lbl = ctk.CTkLabel(row, text=entry.name, width=150, anchor="w",
                                font=(FONT_FAMILY, 12))
        name_lbl.pack(side="left", padx=2)
        dns_lbl = ctk.CTkLabel(row, text="…", width=95, anchor="e", text_color=COLOR_MUTED)
        dns_lbl.pack(side="left", padx=2)
        dloss_lbl = ctk.CTkLabel(row, text="", width=80, anchor="e", text_color=COLOR_MUTED)
        dloss_lbl.pack(side="left", padx=2)
        ping_lbl = ctk.CTkLabel(row, text="", width=80, anchor="e", text_color=COLOR_MUTED)
        ping_lbl.pack(side="left", padx=2)
        loss_lbl = ctk.CTkLabel(row, text="", width=70, anchor="e", text_color=COLOR_MUTED)
        loss_lbl.pack(side="left", padx=2)
        score_lbl = ctk.CTkLabel(row, text="", width=70, anchor="e",
                                 font=(FONT_FAMILY, 12, "bold"))
        score_lbl.pack(side="left", padx=2)
        use_btn = ctk.CTkButton(row, text="Use", width=56, height=26,
                                fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                                command=lambda n=entry.name: self._use(n))
        use_btn.pack(side="left", padx=2)
        self._rows[entry.name] = {
            "row": row, "server": server, "dns": dns_lbl, "dloss": dloss_lbl,
            "ping": ping_lbl, "loss": loss_lbl, "score": score_lbl, "use": use_btn,
        }

    def _start(self):
        self._done = 0
        self.results = []
        self.retest_btn.configure(state="disabled")
        for w in self._rows.values():
            w["dns"].configure(text="…", text_color=COLOR_MUTED)
            for k in ("dloss", "ping", "loss", "score"):
                w[k].configure(text="")
        import concurrent.futures as cf

        def work():
            with cf.ThreadPoolExecutor(max_workers=12) as ex:
                futs = {ex.submit(probe_dns, w["server"]): n
                        for n, w in self._rows.items()}
                for fut in cf.as_completed(futs):
                    nm = futs[fut]
                    try:
                        res = fut.result()
                    except Exception:
                        res = {"server": self._rows[nm]["server"], "ok": False,
                               "score": float("inf"), "ping_ms": -1, "ping_loss": 100,
                               "dns_ms": -1, "dns_loss": 100}
                    res["name"] = nm
                    self.after(0, lambda r=res: self._row_done(r))
            self.after(0, self._all_done)

        threading.Thread(target=work, daemon=True).start()

    def _row_done(self, res: dict):
        try:
            w = self._rows[res["name"]]
        except KeyError:
            return
        self.results.append(res)
        dns_ms, dns_loss = res["dns_ms"], res["dns_loss"]
        ping_ms_v, ping_loss = res["ping_ms"], res["ping_loss"]
        w["dns"].configure(
            text=f"{dns_ms:.0f} ms" if dns_ms >= 0 else "fail",
            text_color=COLOR_TEXT if dns_ms >= 0 else COLOR_DANGER)
        w["dloss"].configure(text=f"{dns_loss:.0f}%",
                             text_color=COLOR_DANGER if dns_loss > 0 else COLOR_MUTED)
        w["ping"].configure(text=f"{ping_ms_v:.0f} ms" if ping_ms_v >= 0 else "—")
        w["loss"].configure(text=f"{ping_loss:.0f}%",
                            text_color=COLOR_DANGER if ping_loss > 0 else COLOR_MUTED)
        sc = res["score"]
        w["score"].configure(
            text="∞" if sc == float("inf") else f"{sc:.0f}",
            text_color=score_color(sc))
        self._done += 1
        self.subtitle.configure(
            text=f"Tested {self._done}/{len(self._rows)} — lower score is better.")

    def _all_done(self):
        self.retest_btn.configure(state="normal")
        # Re-order rows best-first.
        order = sorted(self._rows.keys(),
                       key=lambda n: next((r["score"] for r in self.results
                                           if r["name"] == n), float("inf")))
        for i, n in enumerate(order):
            w = self._rows[n]
            w["row"].pack_forget()
            w["row"].pack(fill="x", pady=2)
            # highlight the winner
            best = (i == 0)
            w["use"].configure(
                fg_color=COLOR_PRIMARY if best else COLOR_SEL,
                hover_color=COLOR_PRIMARY_HOVER if best else COLOR_HOVER)
        self.subtitle.configure(
            text=f"Done — {len(self.results)} tested. Best on top. "
                 f"Click Use to apply.")

    def _use(self, name: str):
        self.chosen = name
        self.destroy()


class OverlayDialog(ctk.CTkToplevel):
    """Configure the on-screen HUD. Changes apply live (the HUD is its own preview)."""
    POSITIONS = ["top-left", "top-right", "bottom-left", "bottom-right"]
    COLORS = appsettings.ACCENT_CHOICES + [("Lime", "#4ade80"), ("White", "#ffffff")]

    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Overlay (HUD)")
        self.geometry("480x700")
        self.configure(fg_color=COLOR_BG)
        self.transient(parent)
        self.grab_set()
        self.app = app
        self._color_map = {n: c for n, c in self.COLORS}
        ov = appsettings.get_overlay()

        body = ctk.CTkScrollableFrame(self, fg_color=COLOR_BG)
        body.pack(fill="both", expand=True, padx=12, pady=12)

        self.enabled_var = ctk.BooleanVar(value=ov.enabled)
        ctk.CTkCheckBox(body, text="Show on-screen overlay (always on top)",
                        variable=self.enabled_var, fg_color=COLOR_PRIMARY,
                        hover_color=COLOR_PRIMARY_HOVER).pack(anchor="w", pady=(4, 10))

        ctk.CTkLabel(body, text="Items to show", font=(FONT_FAMILY, 13, "bold"),
                     anchor="w").pack(fill="x")
        self.dl_var = ctk.BooleanVar(value=ov.show_download)
        self.ul_var = ctk.BooleanVar(value=ov.show_upload)
        self.ping_var = ctk.BooleanVar(value=ov.show_ping)
        self.graph_var = ctk.BooleanVar(value=ov.show_graph)
        for txt, var in (("Download", self.dl_var), ("Upload", self.ul_var),
                         ("Ping", self.ping_var),
                         ("Monitoring signal (speed graph)", self.graph_var)):
            ctk.CTkCheckBox(body, text=txt, variable=var, fg_color=COLOR_PRIMARY,
                            hover_color=COLOR_PRIMARY_HOVER).pack(anchor="w", pady=2)

        grid = ctk.CTkFrame(body, fg_color="transparent")
        grid.pack(fill="x", pady=(10, 0))
        grid.grid_columnconfigure(1, weight=1)
        self._row = 0

        cur_color = next((n for n, c in self.COLORS if c == ov.color), "Lime")
        self.pos_var = self._menu(grid, "Position", self.POSITIONS, ov.position)
        self.font_var = self._menu(grid, "Font", appsettings.FONT_CHOICES, ov.font_family)
        self.color_var = self._menu(grid, "Color", [n for n, _ in self.COLORS], cur_color)
        self.size_var = self._menu(grid, "Text size",
                                   ["10", "11", "12", "13", "14", "16", "18", "20", "24"],
                                   str(ov.font_size))
        self.opacity_var = self._menu(grid, "Opacity",
                                      ["0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"],
                                      f"{ov.opacity:.1f}")
        self.pad_var = self._menu(grid, "Box padding",
                                  ["4", "8", "12", "16", "20", "28"], str(ov.padding))
        self.spc_var = self._menu(grid, "Item spacing",
                                  ["0", "2", "4", "6", "8", "12"], str(ov.spacing))
        self.margin_var = self._menu(grid, "Edge margin",
                                     ["0", "12", "24", "40", "60", "100"], str(ov.margin))
        self.refresh_var = self._menu(grid, "Refresh (ms)",
                                      ["100", "250", "500", "1000", "2000"],
                                      str(ov.refresh_ms))

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkButton(btns, text="Apply", width=110, fg_color=COLOR_PRIMARY,
                      hover_color=COLOR_PRIMARY_HOVER, command=self._save).pack(side="right")
        ctk.CTkButton(btns, text="Close", width=90, fg_color=COLOR_SEL,
                      hover_color=COLOR_HOVER, command=self.destroy).pack(
            side="right", padx=(0, 8))
        self.bind("<Escape>", lambda e: self.destroy())

    def _menu(self, grid, label, values, current):
        ctk.CTkLabel(grid, text=label).grid(row=self._row, column=0, sticky="w", pady=5)
        var = ctk.StringVar(value=current)
        ctk.CTkOptionMenu(grid, variable=var, values=values, width=200,
                          fg_color=COLOR_SEL, button_color=COLOR_SEL,
                          button_hover_color=COLOR_HOVER,
                          dropdown_fg_color=COLOR_PANEL).grid(
            row=self._row, column=1, sticky="e", padx=8, pady=5)
        self._row += 1
        return var

    def _save(self):
        ov = appsettings.OverlayPrefs(
            enabled=self.enabled_var.get(),
            position=self.pos_var.get(),
            show_download=self.dl_var.get(),
            show_upload=self.ul_var.get(),
            show_ping=self.ping_var.get(),
            show_graph=self.graph_var.get(),
            font_family=self.font_var.get(),
            font_size=int(self.size_var.get()),
            color=self._color_map.get(self.color_var.get(), "#4ade80"),
            opacity=float(self.opacity_var.get()),
            padding=int(self.pad_var.get()),
            spacing=int(self.spc_var.get()),
            margin=int(self.margin_var.get()),
            refresh_ms=int(self.refresh_var.get()),
        )
        appsettings.set_overlay(ov)
        try:
            self.app._reload_overlay()
        except Exception:
            pass


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
        self._dns_ping: dict[str, float] = {}       # name -> DNS query rtt (ms)
        self._dns_score: dict[str, float] = {}      # name -> probe score (rank)
        self._dns_status_shown: str | None = None   # last rendered status string
        self._dns_status_last: float = 0.0          # throttle adapter DNS reads
        self._dns_status_busy: bool = False
        # tray
        self._tray = None
        self._tray_state = None
        # overlay HUD + latest values it reads
        self._overlay = None
        self._ov = appsettings.get_overlay()
        self._hud = {"active": False, "down": 0.0, "up": 0.0, "ping": -1.0}

        ctk.set_appearance_mode("dark")
        self._build()
        self._refresh_dns_menu()
        if self._sidebar_collapsed:
            self.side.configure(width=1)
            self.side.grid_remove()
            self._side_visible = False
        self._setup_tray()
        if self._ov.enabled:
            self._create_overlay()

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
        dns_bar.grid_columnconfigure(0, weight=1)

        statrow = ctk.CTkFrame(dns_bar, fg_color="transparent")
        statrow.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 2))
        ctk.CTkLabel(statrow, text="DNS", text_color=COLOR_MUTED,
                     font=(FONT_FAMILY, 10, "bold")).pack(side="left")
        self.dns_status_dot = ctk.CTkLabel(statrow, text="●", text_color=COLOR_MUTED,
                                            font=(FONT_FAMILY, 14))
        self.dns_status_dot.pack(side="left", padx=(10, 5))
        self.dns_status_lbl = ctk.CTkLabel(statrow, text="—", text_color=COLOR_TEXT,
                                           font=(FONT_FAMILY, 12), anchor="w")
        self.dns_status_lbl.pack(side="left", fill="x", expand=True)

        ctrl = ctk.CTkFrame(dns_bar, fg_color="transparent")
        ctrl.grid(row=1, column=0, sticky="ew", padx=10, pady=(2, 10))
        ctrl.grid_columnconfigure(0, weight=1)
        self.dns_var = ctk.StringVar(value="Default")
        self.dns_menu = ctk.CTkOptionMenu(
            ctrl, variable=self.dns_var, values=["Default"],
            command=self._on_dns_select,
            fg_color=COLOR_SEL, button_color=COLOR_SEL,
            button_hover_color=COLOR_HOVER, dropdown_fg_color=COLOR_PANEL)
        self.dns_menu.grid(row=0, column=0, sticky="ew", padx=(4, 6))
        self.dns_apply_btn = ctk.CTkButton(
            ctrl, text="Set", width=58, height=28,
            fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
            command=self._on_dns_apply)
        self.dns_apply_btn.grid(row=0, column=1, padx=3)
        self.dns_reset_btn = ctk.CTkButton(
            ctrl, text="Unset", width=64, height=28,
            fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
            command=self._on_dns_reset)
        self.dns_reset_btn.grid(row=0, column=2, padx=3)
        self.dns_test_btn = ctk.CTkButton(
            ctrl, text="Test all", width=76, height=28,
            fg_color=COLOR_SEL, hover_color=COLOR_HOVER, command=self._on_dns_test)
        self.dns_test_btn.grid(row=0, column=3, padx=3)
        ctk.CTkButton(ctrl, text="Manage", width=72, height=28,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=self._open_dns_manager).grid(row=0, column=4, padx=(3, 4))
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
        # Rank best-first: by probe score if we have one, else by DNS rtt.
        if self._dns_score or self._dns_ping:
            def rank(e):
                sc = self._dns_score.get(e.name)
                if sc is not None:
                    return sc
                ms = self._dns_ping.get(e.name, -1)
                return ms if ms >= 0 else 1e9
            entries.sort(key=rank)
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

    def _on_dns_apply(self):
        """Re-apply the DNS currently chosen in the dropdown to the live adapter."""
        name = self._dns_label_to_name.get(self.dns_var.get(), "")
        if self.current:
            appsettings.set_selected_dns(self.current, name)
        self._apply_dns_now(name)

    def _on_dns_reset(self):
        """Unset custom DNS: revert the adapter to the .conf's DNS (or DHCP)."""
        if self.current:
            appsettings.set_selected_dns(self.current, "")
        self.dns_var.set("Default")
        self._apply_dns_now("")     # empty => tunnel.set_dns reverts to config/DHCP

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
            else:
                self.after(400, lambda: self._refresh_dns_status(force=True))
        threading.Thread(target=work, daemon=True).start()

    def _refresh_dns_status(self, force: bool = False):
        """Read the DNS actually configured on the live adapter and reflect it
        in the status line (which server is set right now). Throttled — reading
        via netsh spawns subprocesses, and the UI ticks twice a second."""
        if not getattr(self, "dns_status_lbl", None):
            return
        if not self.current or not wgapi.is_active(self.current):
            self.dns_status_dot.configure(text_color=COLOR_MUTED)
            self.dns_status_lbl.configure(text="Connect to set DNS",
                                          text_color=COLOR_MUTED)
            self._dns_status_shown = None
            return
        now = time.time()
        if not force and (self._dns_status_busy or now - self._dns_status_last < 3.0):
            return
        self._dns_status_last = now
        self._dns_status_busy = True
        name = self.current

        def work():
            try:
                servers = wgapi.get_dns(name) or []
            except Exception:
                servers = []
            self.after(0, lambda: self._finish_dns_status(name, servers))
        threading.Thread(target=work, daemon=True).start()

    def _finish_dns_status(self, name: str, servers: list[str]):
        self._dns_status_busy = False
        self._render_dns_status(name, servers)

    def _render_dns_status(self, name: str, servers: list[str]):
        if name != self.current:
            return
        key = ",".join(servers)
        if key == self._dns_status_shown:
            return
        self._dns_status_shown = key
        if not servers:
            self.dns_status_dot.configure(text_color=COLOR_MUTED)
            self.dns_status_lbl.configure(text="Automatic (DHCP) — not set",
                                          text_color=COLOR_MUTED)
            return
        # Map the live servers back to a catalog name, if any matches.
        label = ""
        sset = set(servers)
        for e in appsettings.get_dns_catalog():
            if set(e.servers) & sset:
                label = e.name
                break
        txt = ", ".join(servers)
        if label:
            txt += f"   ({label})"
        self.dns_status_dot.configure(text_color=COLOR_OK)
        self.dns_status_lbl.configure(text=txt, text_color=COLOR_TEXT)

    def _on_dns_test(self):
        entries = [e for e in appsettings.get_enabled_dns() if e.servers]
        if not entries:
            messagebox.showinfo("DNS test", "No enabled DNS servers to test.",
                                parent=self)
            return
        d = DnsTestDialog(self, entries)
        self.wait_window(d)
        # Pull the ranking the dialog produced so the home dropdown re-sorts.
        if d.results:
            for r in d.results:
                self._dns_score[r["name"]] = r["score"]
                self._dns_ping[r["name"]] = r["dns_ms"]
            self._refresh_dns_menu()
        if d.chosen is not None:
            if self.current:
                appsettings.set_selected_dns(self.current, d.chosen)
            self._refresh_dns_menu()
            self._apply_dns_now(d.chosen)

    def _open_dns_manager(self):
        d = DnsManagerDialog(self)
        self.wait_window(d)
        if d.changed:
            self._dns_ping.clear()
            self._dns_score.clear()
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

    # --- overlay HUD ---
    def _create_overlay(self):
        try:
            self._overlay = OverlayHUD(self, self._ov, lambda: self._hud)
        except Exception:
            self._overlay = None

    def _destroy_overlay(self):
        if self._overlay:
            try:
                self._overlay.destroy()
            except Exception:
                pass
            self._overlay = None

    def _reload_overlay(self):
        self._ov = appsettings.get_overlay()
        self._destroy_overlay()
        if self._ov.enabled:
            self._create_overlay()

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

        # Set/Unset apply to the live adapter, so they're enabled only while
        # connected. "Test all" works any time (it probes resolvers directly).
        if self._ui.dns_changer_enabled:
            live = "normal" if active else "disabled"
            self.dns_menu.configure(state=live)
            self.dns_apply_btn.configure(state=live)
            self.dns_reset_btn.configure(state=live)
            self._refresh_dns_status()

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

        self._hud = {"active": active, "down": drx, "up": dtx,
                     "ping": self.last_ping_ms}
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
        self._destroy_overlay()
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
