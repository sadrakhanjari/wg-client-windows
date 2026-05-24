import sys
import time
import socket
import ctypes
import threading
import subprocess
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

import wgapi


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


class StatsPoller(threading.Thread):
    """Polls is_active + get_stats for the currently selected tunnel in background."""
    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()
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
        self._stop.set()
        self._wake.set()

    def get_snapshot(self) -> dict:
        with self._lock:
            return dict(self._snapshot)

    def run(self):
        while not self._stop.is_set():
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
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def _ping_once(self) -> float:
        try:
            ip = socket.gethostbyname(self.host)
        except Exception:
            return -1.0
        try:
            r = subprocess.run(
                ["ping", "-n", "1", "-w", "1500", ip],
                capture_output=True, text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW
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

    def run(self):
        while not self._stop.is_set():
            ms = self._ping_once()
            if not self._stop.is_set():
                try:
                    self.callback(self.host, ms)
                except Exception:
                    return
            self._stop.wait(1.0)


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


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Local WireGuard")
        self.geometry("960x600")
        self.minsize(820, 480)
        self.configure(fg_color=COLOR_BG)

        self.current: str | None = None
        self.activated_at: dict[str, float] = {}
        self.last_stats: dict[str, tuple[float, int, int]] = {}
        self.ping_thread: PingThread | None = None
        self.last_ping_ms: float = -1.0
        self.tunnel_buttons: dict[str, ctk.CTkButton] = {}
        self._busy: bool = False
        self._current_ping_host: str | None = None

        ctk.set_appearance_mode("dark")
        self._build()

        self.poller = StatsPoller()
        self.poller.start()

        self.refresh_tunnels()
        self.after(300, self._tick)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        side = ctk.CTkFrame(self, fg_color="#232428", corner_radius=0, width=240)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(1, weight=1)
        side.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(side, text="Tunnels", font=(FONT_FAMILY, 16, "bold"),
                     anchor="w").grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 6))

        self.list_frame = ctk.CTkScrollableFrame(side, fg_color="transparent")
        self.list_frame.grid(row=1, column=0, sticky="nsew", padx=6)

        btn_row = ctk.CTkFrame(side, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        btn_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(btn_row, text="+ Add", height=32,
                      fg_color=COLOR_SEL, hover_color=COLOR_HOVER,
                      command=self.on_add).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(btn_row, text="Delete", height=32,
                      fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER,
                      command=self.on_delete).grid(row=0, column=1, sticky="ew", padx=(4, 0))

        self.detail = ctk.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0)
        self.detail.grid(row=0, column=1, sticky="nsew")
        self.detail.grid_columnconfigure(0, weight=1)

        self.empty_lbl = ctk.CTkLabel(self.detail, text="Select or add a tunnel",
                                       text_color=COLOR_MUTED, font=(FONT_FAMILY, 13))

        head = ctk.CTkFrame(self.detail, fg_color="transparent")
        head.grid_columnconfigure(0, weight=1)
        self.name_lbl = ctk.CTkLabel(head, text="—", font=(FONT_FAMILY, 20, "bold"), anchor="w")
        self.name_lbl.grid(row=0, column=0, sticky="ew")
        self.status_lbl = ctk.CTkLabel(head, text="Inactive", text_color=COLOR_MUTED,
                                        font=(FONT_FAMILY, 12, "bold"), anchor="e")
        self.status_lbl.grid(row=0, column=1, sticky="e")

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

        self.detail_widgets = (head, btns, card)
        self._show_empty()

    def _show_empty(self):
        for w in self.detail_widgets:
            w.grid_forget()
        self.empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

    def _show_detail(self):
        self.empty_lbl.place_forget()
        head, btns, card = self.detail_widgets
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(22, 6))
        btns.grid(row=1, column=0, sticky="w", padx=24, pady=(0, 14))
        card.grid(row=2, column=0, sticky="new", padx=24, pady=(0, 24))

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

    def on_toggle(self):
        if not self.current or self._busy: return
        name = self.current
        self._set_busy(True)
        self.toggle_btn.configure(text="…")
        threading.Thread(target=self._toggle_worker, args=(name,), daemon=True).start()

    def _toggle_worker(self, name: str):
        try:
            if wgapi.is_active(name):
                ok, msg = wgapi.deactivate(name)
            else:
                active = wgapi.get_active_tunnel()
                if active and active != name:
                    wgapi.deactivate(active)
                ok, msg = wgapi.activate(name)
                if ok:
                    self.activated_at[name] = time.time()
        except Exception as e:
            ok, msg = False, str(e)
        self.after(0, lambda: self._after_toggle(ok, msg))

    def _after_toggle(self, ok: bool, msg: str):
        self._set_busy(False)
        if not ok:
            messagebox.showerror("Operation failed", msg, parent=self)
        self.poller.poke()

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
                self.status_lbl.configure(text="● Active", text_color=COLOR_OK)
                self.toggle_btn.configure(text="Disconnect",
                                           fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER)
            else:
                self.status_lbl.configure(text="Inactive", text_color=COLOR_MUTED)
                self.toggle_btn.configure(text="Connect",
                                           fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER)

        if active and stats:
            rx = stats["rx_bytes"]; tx = stats["tx_bytes"]
            now = time.time()
            prev = self.last_stats.get(self.current)
            if prev:
                dt = max(now - prev[0], 0.001)
                drx = max(rx - prev[1], 0) / dt
                dtx = max(tx - prev[2], 0) / dt
                self.stats_widgets["down"].configure(text=fmt_rate(drx))
                self.stats_widgets["up"].configure(text=fmt_rate(dtx))
            else:
                self.stats_widgets["down"].configure(text="0.0 B/s")
                self.stats_widgets["up"].configure(text="0.0 B/s")
            self.last_stats[self.current] = (now, rx, tx)
            self.stats_widgets["rx"].configure(text=fmt_bytes(rx))
            self.stats_widgets["tx"].configure(text=fmt_bytes(tx))
            self.stats_widgets["ep"].configure(text=stats["endpoint"] or "—")
            if self.current not in self.activated_at:
                self.activated_at[self.current] = now
            self.stats_widgets["uptime"].configure(
                text=fmt_duration(int(now - self.activated_at[self.current])))

            host = None
            if (wgapi.CONF_DIR / f"{self.current}.conf").exists():
                host = wgapi.parse_endpoint_host(wgapi.read_tunnel_config(self.current) or "")
            if not host and stats["endpoint"]:
                host = stats["endpoint"].rsplit(":", 1)[0].strip("[]")
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
        else:
            self._stop_ping()
            for k in ("ping", "uptime", "down", "up", "rx", "tx", "ep"):
                self.stats_widgets[k].configure(text="—")
            self.last_stats.pop(self.current, None)
            self.activated_at.pop(self.current, None)

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
        self.poller.stop()
        self.destroy()


def main():
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
