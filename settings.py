"""App settings (auto-reconnect knobs etc.) persisted to JSON.

Storage: %LOCALAPPDATA%\\LocalWireGuard\\settings.json

Global defaults can be overridden per-tunnel.
"""
import os
import json
import threading
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Any


SETTINGS_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LocalWireGuard"
SETTINGS_PATH = SETTINGS_DIR / "settings.json"


@dataclass
class AutoReconnect:
    enabled: bool = False
    min_kbps: int = 50              # below this triggers reconnect
    window_sec: int = 10            # how long below threshold before triggering
    delay_sec: int = 10             # wait this long between disconnect and reconnect


@dataclass
class Settings:
    auto_reconnect: AutoReconnect = field(default_factory=AutoReconnect)
    per_tunnel: dict[str, dict] = field(default_factory=dict)


_lock = threading.Lock()
_cache: Settings | None = None


def _from_dict(data: dict) -> Settings:
    ar = data.get("auto_reconnect", {})
    return Settings(
        auto_reconnect=AutoReconnect(
            enabled=bool(ar.get("enabled", False)),
            min_kbps=int(ar.get("min_kbps", 50)),
            window_sec=int(ar.get("window_sec", 10)),
            delay_sec=int(ar.get("delay_sec", 10)),
        ),
        per_tunnel=dict(data.get("per_tunnel", {})),
    )


def load() -> Settings:
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
        if SETTINGS_PATH.exists():
            try:
                data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
                _cache = _from_dict(data)
                return _cache
            except Exception:
                pass
        _cache = Settings()
        return _cache


def save(settings: Settings) -> None:
    global _cache
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "auto_reconnect": asdict(settings.auto_reconnect),
        "per_tunnel": settings.per_tunnel,
    }
    SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    with _lock:
        _cache = settings


def get_auto_reconnect_for(tunnel_name: str) -> AutoReconnect:
    """Return effective auto-reconnect settings for a tunnel (per-tunnel override + global)."""
    s = load()
    base = AutoReconnect(**asdict(s.auto_reconnect))
    over = s.per_tunnel.get(tunnel_name, {}).get("auto_reconnect")
    if isinstance(over, dict):
        for k, v in over.items():
            if hasattr(base, k):
                setattr(base, k, v)
    return base


def set_auto_reconnect_global(ar: AutoReconnect) -> None:
    s = load()
    s.auto_reconnect = ar
    save(s)


def set_auto_reconnect_per_tunnel(tunnel_name: str, ar: AutoReconnect | None) -> None:
    s = load()
    if ar is None:
        s.per_tunnel.pop(tunnel_name, None)
    else:
        s.per_tunnel.setdefault(tunnel_name, {})["auto_reconnect"] = asdict(ar)
    save(s)
