import os
import re
import time
import ctypes
import ctypes.wintypes as wt
import subprocess
import configparser
from pathlib import Path
from typing import Optional


WG_DIR = Path(r"C:\Users\PCMOD\Desktop\vpn")
WG_EXE = WG_DIR / "wireguard.exe"
CONF_DIR = WG_DIR / "Data" / "Configurations"


# --- Win32 named pipe ---
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value
ERROR_PIPE_BUSY = 231

_CreateFileW = _kernel32.CreateFileW
_CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
_CreateFileW.restype = wt.HANDLE

_WriteFile = _kernel32.WriteFile
_WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
_WriteFile.restype = wt.BOOL

_ReadFile = _kernel32.ReadFile
_ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
_ReadFile.restype = wt.BOOL

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wt.HANDLE]
_CloseHandle.restype = wt.BOOL

_WaitNamedPipeW = _kernel32.WaitNamedPipeW
_WaitNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD]
_WaitNamedPipeW.restype = wt.BOOL


def _pipe_path(name: str) -> str:
    return rf"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\{name}"


def _read_uapi(name: str, timeout_ms: int = 500) -> Optional[str]:
    path = _pipe_path(name)
    handle = _CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, 0)
    if handle == INVALID_HANDLE_VALUE:
        if ctypes.get_last_error() == ERROR_PIPE_BUSY:
            if not _WaitNamedPipeW(path, timeout_ms):
                return None
            handle = _CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, 0)
            if handle == INVALID_HANDLE_VALUE:
                return None
        else:
            return None
    try:
        msg = b"get=1\n\n"
        written = wt.DWORD(0)
        if not _WriteFile(handle, msg, len(msg), ctypes.byref(written), None):
            return None
        chunks = []
        buf = ctypes.create_string_buffer(8192)
        read = wt.DWORD(0)
        while True:
            ok = _ReadFile(handle, buf, 8192, ctypes.byref(read), None)
            if not ok or read.value == 0:
                break
            chunk = buf.raw[:read.value]
            chunks.append(chunk)
            if b"\n\n" in b"".join(chunks):
                break
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        _CloseHandle(handle)


def get_stats(name: str) -> Optional[dict]:
    data = _read_uapi(name)
    if not data:
        return None
    rx = tx = 0
    last_handshake = 0
    endpoint = ""
    for line in data.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k == "rx_bytes":
            try: rx += int(v)
            except: pass
        elif k == "tx_bytes":
            try: tx += int(v)
            except: pass
        elif k == "last_handshake_time_sec":
            try: last_handshake = max(last_handshake, int(v))
            except: pass
        elif k == "endpoint" and not endpoint:
            endpoint = v
    return {"rx_bytes": rx, "tx_bytes": tx, "last_handshake": last_handshake, "endpoint": endpoint}


# --- Tunnel mgmt ---
def list_tunnels() -> list[dict]:
    if not CONF_DIR.exists():
        return []
    out = []
    for f in CONF_DIR.iterdir():
        n = f.name
        if n.endswith(".conf.dpapi"):
            out.append({"name": n[:-len(".conf.dpapi")], "path": f, "encrypted": True})
        elif n.endswith(".conf"):
            out.append({"name": n[:-len(".conf")], "path": f, "encrypted": False})
    out.sort(key=lambda x: x["name"].lower())
    return out


def is_active(name: str) -> bool:
    try:
        r = subprocess.run(["sc", "query", f"WireGuardTunnel${name}"],
                           capture_output=True, text=True, timeout=5)
        return "RUNNING" in r.stdout
    except Exception:
        return False


def activate(name: str) -> tuple[bool, str]:
    tunnels = {t["name"]: t for t in list_tunnels()}
    if name not in tunnels:
        return False, f"Tunnel {name} not found"
    path = tunnels[name]["path"]
    try:
        r = subprocess.run([str(WG_EXE), "/installtunnelservice", str(path)],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout or "failed").strip()
        for _ in range(20):
            if is_active(name):
                return True, "ok"
            time.sleep(0.3)
        return True, "started"
    except Exception as e:
        return False, str(e)


def deactivate(name: str) -> tuple[bool, str]:
    try:
        r = subprocess.run([str(WG_EXE), "/uninstalltunnelservice", name],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout or "failed").strip()
        return True, "ok"
    except Exception as e:
        return False, str(e)


def get_active_tunnel() -> Optional[str]:
    try:
        r = subprocess.run(["sc", "query", "type=", "service", "state=", "all"],
                           capture_output=True, text=True, timeout=10)
        for m in re.finditer(r"SERVICE_NAME:\s*WireGuardTunnel\$(\S+)", r.stdout):
            tn = m.group(1)
            if is_active(tn):
                return tn
    except Exception:
        pass
    return None


def add_tunnel(name: str, conf_text: str) -> tuple[bool, str]:
    if not re.match(r"^[A-Za-z0-9_=+.-]{1,32}$", name):
        return False, "Invalid name (1-32 chars: letters, digits, _ = + . -)"
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    dest = CONF_DIR / f"{name}.conf"
    if dest.exists() or (CONF_DIR / f"{name}.conf.dpapi").exists():
        return False, f"Tunnel '{name}' already exists"
    try:
        dest.write_text(conf_text, encoding="utf-8")
        return True, "ok"
    except Exception as e:
        return False, str(e)


def delete_tunnel(name: str) -> tuple[bool, str]:
    if is_active(name):
        deactivate(name)
    removed = False
    for ext in (".conf", ".conf.dpapi"):
        p = CONF_DIR / f"{name}{ext}"
        if p.exists():
            try:
                p.unlink()
                removed = True
            except Exception as e:
                return False, str(e)
    return (removed, "ok" if removed else "Not found")


def read_tunnel_config(name: str) -> Optional[str]:
    p = CONF_DIR / f"{name}.conf"
    if p.exists():
        try:
            return p.read_text(encoding="utf-8")
        except Exception:
            return None
    if (CONF_DIR / f"{name}.conf.dpapi").exists():
        return "[Encrypted by WireGuard (.dpapi). Editing not supported — delete and recreate.]"
    return None


def update_tunnel(name: str, conf_text: str) -> tuple[bool, str]:
    p = CONF_DIR / f"{name}.conf"
    if not p.exists():
        if (CONF_DIR / f"{name}.conf.dpapi").exists():
            return False, "Encrypted tunnel cannot be edited"
        return False, "Tunnel not found"
    was_active = is_active(name)
    if was_active:
        deactivate(name)
        time.sleep(0.3)
    try:
        p.write_text(conf_text, encoding="utf-8")
    except Exception as e:
        return False, str(e)
    if was_active:
        activate(name)
    return True, "ok"


def parse_endpoint_host(conf_text: str) -> Optional[str]:
    cp = configparser.ConfigParser(strict=False)
    try:
        cp.read_string(conf_text)
    except Exception:
        return None
    for sect in cp.sections():
        if sect.lower() == "peer":
            ep = cp.get(sect, "Endpoint", fallback="")
            if ep:
                host = ep.rsplit(":", 1)[0]
                return host.strip("[]")
    return None


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
