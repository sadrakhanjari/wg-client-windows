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
class DnsEntry:
    name: str
    servers: list[str]              # e.g. ["1.1.1.1", "1.0.0.1"]
    enabled: bool = True


# 30 curated public resolvers — the user can add/edit/delete/disable these.
DEFAULT_DNS_CATALOG: list[DnsEntry] = [
    DnsEntry("Cloudflare", ["1.1.1.1", "1.0.0.1"]),
    DnsEntry("Cloudflare Malware", ["1.1.1.2", "1.0.0.2"]),
    DnsEntry("Cloudflare Family", ["1.1.1.3", "1.0.0.3"]),
    DnsEntry("Google", ["8.8.8.8", "8.8.4.4"]),
    DnsEntry("Quad9", ["9.9.9.9", "149.112.112.112"]),
    DnsEntry("Quad9 Unsecured", ["9.9.9.10", "149.112.112.10"]),
    DnsEntry("OpenDNS Home", ["208.67.222.222", "208.67.220.220"]),
    DnsEntry("OpenDNS FamilyShield", ["208.67.222.123", "208.67.220.123"]),
    DnsEntry("AdGuard", ["94.140.14.14", "94.140.15.15"]),
    DnsEntry("AdGuard Family", ["94.140.14.15", "94.140.15.16"]),
    DnsEntry("AdGuard Non-filtering", ["94.140.14.140", "94.140.14.141"]),
    DnsEntry("CleanBrowsing Security", ["185.228.168.9", "185.228.169.9"]),
    DnsEntry("CleanBrowsing Family", ["185.228.168.168", "185.228.169.168"]),
    DnsEntry("CleanBrowsing Adult", ["185.228.168.10", "185.228.169.11"]),
    DnsEntry("Comodo Secure", ["8.26.56.26", "8.20.247.20"]),
    DnsEntry("Verisign", ["64.6.64.6", "64.6.65.6"]),
    DnsEntry("Neustar UltraDNS", ["156.154.70.1", "156.154.71.1"]),
    DnsEntry("Level3", ["4.2.2.1", "4.2.2.2"]),
    DnsEntry("DNS.WATCH", ["84.200.69.80", "84.200.70.40"]),
    DnsEntry("Yandex Basic", ["77.88.8.8", "77.88.8.1"]),
    DnsEntry("Yandex Safe", ["77.88.8.88", "77.88.8.2"]),
    DnsEntry("Yandex Family", ["77.88.8.7", "77.88.8.3"]),
    DnsEntry("Mullvad", ["194.242.2.2"]),
    DnsEntry("Mullvad Adblock", ["194.242.2.3"]),
    DnsEntry("ControlD Unfiltered", ["76.76.2.0", "76.76.10.0"]),
    DnsEntry("ControlD Malware", ["76.76.2.1", "76.76.10.1"]),
    DnsEntry("NextDNS", ["45.90.28.0", "45.90.30.0"]),
    DnsEntry("Alternate DNS", ["76.76.19.19", "76.223.122.150"]),
    DnsEntry("Gcore", ["95.85.95.85", "2.56.220.2"]),
    DnsEntry("DNS0.eu", ["193.110.81.0", "185.253.5.0"]),

    # --- Iran: anti-sanction / gaming resolvers (unblock game launchers &
    #     stores like Steam/Epic/PSN from inside Iran, lower game latency) ---
    DnsEntry("Shecan (IR)", ["178.22.122.100", "185.51.200.2"]),
    DnsEntry("403 (IR · gaming)", ["10.202.10.202", "10.202.10.102"]),
    DnsEntry("RadarGame (IR · gaming)", ["10.202.10.10", "10.202.10.11"]),
    DnsEntry("Electro (IR · gaming)", ["78.157.42.100", "78.157.42.101"]),
    DnsEntry("Begzar (IR)", ["185.55.226.26", "185.55.225.25"]),
    DnsEntry("Shelter (IR · gaming)", ["94.103.125.157", "94.103.125.158"]),
    DnsEntry("Pishgaman (IR)", ["5.202.100.100", "5.202.100.101"]),
    DnsEntry("Iran TCI", ["217.218.155.155", "217.218.127.127"]),

    # --- More public resolvers (filtering tiers of major providers) ---
    DnsEntry("Quad9 ECS", ["9.9.9.11", "149.112.112.11"]),
    DnsEntry("Level3 (3/4)", ["4.2.2.3", "4.2.2.4"]),
    DnsEntry("Level3 (5/6)", ["4.2.2.5", "4.2.2.6"]),
    DnsEntry("Neustar Threat", ["156.154.70.2", "156.154.71.2"]),
    DnsEntry("Neustar Family", ["156.154.70.3", "156.154.71.3"]),
    DnsEntry("Neustar Business", ["156.154.70.4", "156.154.71.4"]),
    DnsEntry("Mullvad Family", ["194.242.2.4"]),
    DnsEntry("Mullvad Extended", ["194.242.2.6"]),
    DnsEntry("Mullvad All", ["194.242.2.9"]),
    DnsEntry("ControlD Ads+Tracking", ["76.76.2.2"]),
    DnsEntry("ControlD Social", ["76.76.2.3"]),
    DnsEntry("ControlD Family", ["76.76.2.5"]),
    DnsEntry("DNS0.eu Kids", ["193.110.81.9", "185.253.5.9"]),
    DnsEntry("DNSFilter", ["103.247.36.36", "103.247.37.37"]),
    DnsEntry("NordVPN", ["103.86.96.100", "103.86.99.100"]),

    # --- Asia (often low-latency for gaming traffic) ---
    DnsEntry("AliDNS", ["223.5.5.5", "223.6.6.6"]),
    DnsEntry("DNSPod", ["119.29.29.29", "182.254.116.116"]),
    DnsEntry("DNSPod Plus", ["1.12.12.12", "120.53.53.53"]),
    DnsEntry("114DNS", ["114.114.114.114", "114.114.115.115"]),
    DnsEntry("114DNS Safe", ["114.114.114.119", "114.114.115.119"]),
    DnsEntry("114DNS Family", ["114.114.114.110", "114.114.115.110"]),
    DnsEntry("Baidu DNS", ["180.76.76.76"]),
    DnsEntry("360 Secure", ["101.226.4.6", "218.30.118.6"]),
    DnsEntry("360 Secure (alt)", ["123.125.81.6", "140.207.198.6"]),
    DnsEntry("CNNIC sDNS", ["1.2.4.8", "210.2.4.8"]),
    DnsEntry("OneDNS", ["117.50.11.11", "52.80.66.66"]),
    DnsEntry("Quad101 (TWNIC)", ["101.101.101.101", "101.102.103.104"]),
    DnsEntry("DNS.SB", ["185.222.222.222", "45.11.45.11"]),
    DnsEntry("Tiarap (SG)", ["174.138.21.128"]),

    # --- Russia / CIS ---
    DnsEntry("SkyDNS", ["193.58.251.251"]),
    DnsEntry("Comss.one", ["92.38.152.163", "93.115.24.204"]),

    # --- Europe (privacy / community resolvers) ---
    DnsEntry("UncensoredDNS", ["91.239.100.100", "89.233.43.71"]),
    DnsEntry("Digitalcourage (DE)", ["5.9.164.112"]),
    DnsEntry("Digitale Gesellschaft (CH)", ["185.95.218.42", "185.95.218.43"]),
    DnsEntry("dnsforge (DE)", ["176.9.93.198", "176.9.1.117"]),
    DnsEntry("ffmuc (DE)", ["5.1.66.255", "185.150.99.255"]),
    DnsEntry("FDN (FR)", ["80.67.169.12", "80.67.169.40"]),
    DnsEntry("LDN (FR)", ["80.67.188.188"]),
    DnsEntry("Aquilenet (FR)", ["185.233.100.100", "185.233.100.101"]),
    DnsEntry("CZ.NIC ODVR", ["193.17.47.1", "185.43.135.1"]),
    DnsEntry("LibreDNS", ["88.198.92.222", "116.202.176.26"]),
    DnsEntry("Restena (LU)", ["158.64.1.29"]),
    DnsEntry("Applied Privacy (AT)", ["146.255.56.98"]),
    DnsEntry("puntCAT", ["109.69.8.51"]),
    DnsEntry("Njalla", ["95.215.19.53"]),
    DnsEntry("Freenom World", ["80.80.80.80", "80.80.81.81"]),
    DnsEntry("SafeDNS", ["195.46.39.39", "195.46.39.40"]),
    DnsEntry("FreeDNS", ["37.235.1.174", "37.235.1.177"]),
    DnsEntry("GreenTeamDNS", ["81.218.119.11", "209.88.198.133"]),
    DnsEntry("AhaDNS", ["5.2.75.75", "45.67.219.208"]),
    DnsEntry("ScrubIT", ["198.54.117.10", "198.54.117.11"]),

    # --- North America ---
    DnsEntry("CIRA Shield Private", ["149.112.121.10", "149.112.122.10"]),
    DnsEntry("CIRA Shield Protected", ["149.112.121.20", "149.112.122.20"]),
    DnsEntry("Hurricane Electric", ["74.82.42.42"]),
    DnsEntry("Dyn", ["216.146.35.35", "216.146.36.36"]),
    DnsEntry("Sprint", ["204.117.214.10", "199.2.252.10"]),
]


@dataclass
class UIPrefs:
    """Feature toggles + remembered UI state + theme. All editable in Settings."""
    dns_changer_enabled: bool = True
    show_country: bool = True
    tray_enabled: bool = True
    sidebar_collapsed: bool = False     # remembered last sidebar state
    font_family: str = "Segoe UI"       # applied app-wide on next launch
    accent: str = "#2c7ef0"             # primary/accent color


# 40 good UI fonts to pick from (Tk falls back gracefully if one isn't installed).
FONT_CHOICES: list[str] = [
    "Segoe UI", "Segoe UI Variable", "Segoe UI Semibold", "Calibri", "Cambria",
    "Candara", "Corbel", "Consolas", "Cascadia Code", "Cascadia Mono",
    "Arial", "Arial Nova", "Helvetica", "Tahoma", "Verdana", "Trebuchet MS",
    "Georgia", "Times New Roman", "Franklin Gothic", "Century Gothic",
    "Lucida Sans", "Lucida Console", "Microsoft Sans Serif", "Gadugi",
    "Ebrima", "Bahnschrift", "Sitka Text", "Selawik", "Open Sans", "Roboto",
    "Roboto Mono", "Lato", "Montserrat", "Source Sans Pro", "Source Code Pro",
    "Fira Code", "JetBrains Mono", "Inter", "Noto Sans", "DejaVu Sans Mono",
]

# Accent color presets.
ACCENT_CHOICES: list[tuple[str, str]] = [
    ("Blue", "#2c7ef0"), ("Indigo", "#5b6ef0"), ("Violet", "#8b5cf6"),
    ("Pink", "#ec4899"), ("Red", "#ef4444"), ("Orange", "#f97316"),
    ("Amber", "#f59e0b"), ("Green", "#22c55e"), ("Teal", "#14b8a6"),
    ("Cyan", "#06b6d4"), ("Slate", "#64748b"),
]


@dataclass
class SplitConfig:
    """Per-tunnel split routing. mode: off | exclude | include."""
    mode: str = "off"
    rules: list[str] = field(default_factory=list)   # IPs / CIDRs / domains


@dataclass
class OverlayPrefs:
    """On-screen HUD showing live speed/ping in a screen corner."""
    enabled: bool = False
    position: str = "top-right"   # top-left | top-right | bottom-left | bottom-right
    show_download: bool = True
    show_upload: bool = True
    show_ping: bool = True
    show_graph: bool = False      # "monitoring signal" mini speed graph
    font_family: str = "Consolas"
    font_size: int = 13
    color: str = "#4ade80"
    opacity: float = 0.80         # window transparency 0.2..1.0
    padding: int = 12             # inner box padding
    spacing: int = 4              # gap between items
    margin: int = 24              # distance from the screen edge
    refresh_ms: int = 500         # how often the HUD refreshes


@dataclass
class Settings:
    auto_reconnect: AutoReconnect = field(default_factory=AutoReconnect)
    ui: UIPrefs = field(default_factory=UIPrefs)
    overlay: OverlayPrefs = field(default_factory=OverlayPrefs)
    dns_catalog: list[DnsEntry] = field(
        default_factory=lambda: [DnsEntry(e.name, list(e.servers), e.enabled)
                                 for e in DEFAULT_DNS_CATALOG])
    per_tunnel: dict[str, dict] = field(default_factory=dict)


_lock = threading.Lock()
_cache: Settings | None = None


def _overlay_from_dict(o: dict) -> OverlayPrefs:
    d = OverlayPrefs()
    pos = str(o.get("position", d.position))
    if pos not in ("top-left", "top-right", "bottom-left", "bottom-right"):
        pos = d.position
    return OverlayPrefs(
        enabled=bool(o.get("enabled", d.enabled)),
        position=pos,
        show_download=bool(o.get("show_download", d.show_download)),
        show_upload=bool(o.get("show_upload", d.show_upload)),
        show_ping=bool(o.get("show_ping", d.show_ping)),
        show_graph=bool(o.get("show_graph", d.show_graph)),
        font_family=str(o.get("font_family", d.font_family)) or d.font_family,
        font_size=max(8, min(48, int(o.get("font_size", d.font_size)))),
        color=str(o.get("color", d.color)) or d.color,
        opacity=max(0.2, min(1.0, float(o.get("opacity", d.opacity)))),
        padding=max(0, min(60, int(o.get("padding", d.padding)))),
        spacing=max(0, min(40, int(o.get("spacing", d.spacing)))),
        margin=max(0, min(400, int(o.get("margin", d.margin)))),
        refresh_ms=max(100, min(5000, int(o.get("refresh_ms", d.refresh_ms)))),
    )


def _from_dict(data: dict) -> Settings:
    ar = data.get("auto_reconnect", {})
    ui = data.get("ui", {})
    cat_raw = data.get("dns_catalog")
    if isinstance(cat_raw, list) and cat_raw:
        catalog = [
            DnsEntry(
                name=str(e.get("name", "")),
                servers=[str(s) for s in e.get("servers", []) if str(s).strip()],
                enabled=bool(e.get("enabled", True)),
            )
            for e in cat_raw if isinstance(e, dict) and e.get("name")
        ]
    else:
        catalog = [DnsEntry(e.name, list(e.servers), e.enabled)
                   for e in DEFAULT_DNS_CATALOG]
    return Settings(
        auto_reconnect=AutoReconnect(
            enabled=bool(ar.get("enabled", False)),
            min_kbps=int(ar.get("min_kbps", 50)),
            window_sec=int(ar.get("window_sec", 10)),
            delay_sec=int(ar.get("delay_sec", 10)),
        ),
        ui=UIPrefs(
            dns_changer_enabled=bool(ui.get("dns_changer_enabled", True)),
            show_country=bool(ui.get("show_country", True)),
            tray_enabled=bool(ui.get("tray_enabled", True)),
            sidebar_collapsed=bool(ui.get("sidebar_collapsed", False)),
            font_family=str(ui.get("font_family", "Segoe UI")) or "Segoe UI",
            accent=str(ui.get("accent", "#2c7ef0")) or "#2c7ef0",
        ),
        overlay=_overlay_from_dict(data.get("overlay", {})),
        dns_catalog=catalog,
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
        "ui": asdict(settings.ui),
        "overlay": asdict(settings.overlay),
        "dns_catalog": [asdict(e) for e in settings.dns_catalog],
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


# ---- UI preferences ----

def get_ui() -> UIPrefs:
    return UIPrefs(**asdict(load().ui))


def set_ui(ui: UIPrefs) -> None:
    s = load()
    s.ui = ui
    save(s)


def set_sidebar_collapsed(collapsed: bool) -> None:
    s = load()
    s.ui.sidebar_collapsed = collapsed
    save(s)


# ---- overlay (HUD) ----

def get_overlay() -> OverlayPrefs:
    return OverlayPrefs(**asdict(load().overlay))


def set_overlay(ov: OverlayPrefs) -> None:
    s = load()
    s.overlay = ov
    save(s)


# ---- DNS catalog ----

def get_dns_catalog() -> list[DnsEntry]:
    return [DnsEntry(e.name, list(e.servers), e.enabled) for e in load().dns_catalog]


def get_enabled_dns() -> list[DnsEntry]:
    return [e for e in get_dns_catalog() if e.enabled and e.servers]


def save_dns_catalog(entries: list[DnsEntry]) -> None:
    s = load()
    s.dns_catalog = [DnsEntry(e.name, list(e.servers), e.enabled) for e in entries]
    save(s)


def get_selected_dns(tunnel_name: str) -> str:
    """Name of the DNS entry chosen for a tunnel, or '' meaning Default."""
    return str(load().per_tunnel.get(tunnel_name, {}).get("dns", ""))


def set_selected_dns(tunnel_name: str, dns_name: str) -> None:
    s = load()
    if dns_name:
        s.per_tunnel.setdefault(tunnel_name, {})["dns"] = dns_name
    else:
        s.per_tunnel.get(tunnel_name, {}).pop("dns", None)
    save(s)


# ---- per-tunnel split routing ----

def get_split(tunnel_name: str) -> SplitConfig:
    raw = load().per_tunnel.get(tunnel_name, {}).get("split", {})
    mode = str(raw.get("mode", "off"))
    if mode not in ("off", "exclude", "include"):
        mode = "off"
    rules = [str(r).strip() for r in raw.get("rules", []) if str(r).strip()]
    return SplitConfig(mode=mode, rules=rules)


def set_split(tunnel_name: str, split: SplitConfig) -> None:
    s = load()
    if split.mode == "off" and not split.rules:
        s.per_tunnel.get(tunnel_name, {}).pop("split", None)
    else:
        s.per_tunnel.setdefault(tunnel_name, {})["split"] = {
            "mode": split.mode,
            "rules": [r.strip() for r in split.rules if r.strip()],
        }
    save(s)
