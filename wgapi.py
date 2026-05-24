"""High-level tunnel management — pure-Python WireGuard backend.

This replaces the Phase 0 wrapper around wireguard.exe. Configs live in
%LOCALAPPDATA%\\LocalWireGuard\\tunnels and tunnels run as in-process
threads managed by tunnel.Tunnel.

Public API (kept compatible with main.py from Phase 0):
    list_tunnels() -> list[dict]
    is_active(name) -> bool
    get_active_tunnel() -> str | None
    activate(name) -> (ok, msg)
    deactivate(name) -> (ok, msg)
    add_tunnel(name, conf_text) -> (ok, msg)
    delete_tunnel(name) -> (ok, msg)
    update_tunnel(name, conf_text) -> (ok, msg)
    read_tunnel_config(name) -> str | None
    get_stats(name) -> dict | None
    parse_endpoint_host(conf_text) -> str | None
    is_admin() -> bool
"""
import os
import re
import ctypes
import threading
from pathlib import Path
from typing import Optional

import tunnel as _tun


CONF_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LocalWireGuard" / "tunnels"
CONF_DIR.mkdir(parents=True, exist_ok=True)

# Sentinel for backward-compat with main.py — Phase 0 checked this path.
# We point to wintun.dll which is our actual runtime dependency.
WG_EXE = Path(__file__).resolve().parent / "vendor" / "wintun.dll"

_lock = threading.Lock()
_active: dict[str, _tun.Tunnel] = {}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def list_tunnels() -> list[dict]:
    if not CONF_DIR.exists():
        return []
    out = []
    for f in CONF_DIR.iterdir():
        if f.suffix.lower() == ".conf":
            out.append({"name": f.stem, "path": f, "encrypted": False})
    out.sort(key=lambda x: x["name"].lower())
    return out


def is_active(name: str) -> bool:
    with _lock:
        t = _active.get(name)
        return bool(t and t.is_running)


def get_active_tunnel() -> Optional[str]:
    with _lock:
        for name, t in _active.items():
            if t.is_running:
                return name
    return None


def _conf_path(name: str) -> Path:
    return CONF_DIR / f"{name}.conf"


def read_tunnel_config(name: str) -> Optional[str]:
    p = _conf_path(name)
    if not p.exists():
        return None
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return None


def _validate_name(name: str) -> Optional[str]:
    if not re.match(r"^[A-Za-z0-9_=+.-]{1,32}$", name):
        return "Invalid name (1-32 chars: letters, digits, _ = + . -)"
    return None


def add_tunnel(name: str, conf_text: str) -> tuple[bool, str]:
    err = _validate_name(name)
    if err:
        return False, err
    p = _conf_path(name)
    if p.exists():
        return False, f"Tunnel '{name}' already exists"
    try:
        _tun.parse_config(conf_text, name=name)
    except Exception as e:
        return False, f"Config invalid: {e}"
    try:
        p.write_text(conf_text, encoding="utf-8")
        return True, "ok"
    except Exception as e:
        return False, str(e)


def update_tunnel(name: str, conf_text: str) -> tuple[bool, str]:
    p = _conf_path(name)
    if not p.exists():
        return False, "Tunnel not found"
    try:
        _tun.parse_config(conf_text, name=name)
    except Exception as e:
        return False, f"Config invalid: {e}"
    was_active = is_active(name)
    if was_active:
        deactivate(name)
    try:
        p.write_text(conf_text, encoding="utf-8")
    except Exception as e:
        return False, str(e)
    if was_active:
        ok, msg = activate(name)
        if not ok:
            return False, f"Saved, but failed to restart: {msg}"
    return True, "ok"


def delete_tunnel(name: str) -> tuple[bool, str]:
    if is_active(name):
        deactivate(name)
    p = _conf_path(name)
    if not p.exists():
        return False, "Tunnel not found"
    try:
        p.unlink()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def activate(name: str) -> tuple[bool, str]:
    with _lock:
        if name in _active and _active[name].is_running:
            return True, "already active"
    text = read_tunnel_config(name)
    if not text:
        return False, "Tunnel not found"
    try:
        cfg = _tun.parse_config(text, name=name)
    except Exception as e:
        return False, f"Config invalid: {e}"
    # Disconnect any other active tunnel (Wintun semantics + routing conflicts)
    other = get_active_tunnel()
    if other and other != name:
        deactivate(other)
    t = _tun.Tunnel(cfg)
    try:
        t.start()
    except Exception as e:
        try:
            t.stop()
        except Exception:
            pass
        return False, f"Activate failed: {e}"
    with _lock:
        _active[name] = t
    return True, "ok"


def deactivate(name: str) -> tuple[bool, str]:
    with _lock:
        t = _active.pop(name, None)
    if t is None:
        return True, "not active"
    try:
        t.stop()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def get_stats(name: str) -> Optional[dict]:
    with _lock:
        t = _active.get(name)
    if not t or not t.is_running:
        return None
    s = t.stats
    # Backward-compat with Phase 0 stats shape used by main.py
    return {
        "rx_bytes": s["rx_bytes"],
        "tx_bytes": s["tx_bytes"],
        "last_handshake": int(s["last_handshake"]),
        "endpoint": s["endpoint"],
    }


def parse_endpoint_host(conf_text: str) -> Optional[str]:
    try:
        cfg = _tun.parse_config(conf_text, name="")
        return cfg.peer_endpoint[0]
    except Exception:
        return None
