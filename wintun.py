"""Wintun TUN driver wrapper via ctypes.

API reference: vendor/wintun.h (from https://www.wintun.net/).
The DLL handles driver install on first CreateAdapter call (requires admin).
"""
import os
import ctypes
import ctypes.wintypes as wt
import struct
import threading
from pathlib import Path
from typing import Optional, Callable


_DLL_DIR = Path(__file__).resolve().parent / "vendor"
_DLL_PATH = _DLL_DIR / "wintun.dll"

WINTUN_MIN_RING_CAPACITY = 0x20000        # 128 KiB
WINTUN_MAX_RING_CAPACITY = 0x4000000      # 64 MiB
WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF
DEFAULT_RING_CAPACITY = 0x400000          # 4 MiB

WINTUN_LOG_INFO = 0
WINTUN_LOG_WARN = 1
WINTUN_LOG_ERR = 2

INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
WAIT_FAILED = 0xFFFFFFFF
ERROR_NO_MORE_ITEMS = 259
ERROR_HANDLE_EOF = 38

# Logger callback signature
WINTUN_LOGGER_CALLBACK = ctypes.WINFUNCTYPE(
    None, ctypes.c_int, ctypes.c_uint64, wt.LPCWSTR
)


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class NET_LUID(ctypes.Union):
    """NET_LUID is a UINT64 with bitfields. We just keep the raw value."""
    _fields_ = [("Value", ctypes.c_uint64)]


class WintunError(OSError):
    """Wintun call failed; carries the Windows error code."""


def _last_error_str() -> str:
    code = ctypes.get_last_error()
    msg = ctypes.FormatError(code)
    return f"WinError {code}: {msg}"


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_WaitForSingleObject = _kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_WaitForSingleObject.restype = wt.DWORD


class _Wintun:
    """Singleton loader for wintun.dll."""
    _instance: Optional["_Wintun"] = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._load()
                cls._instance = inst
            return cls._instance

    def _load(self) -> None:
        if not _DLL_PATH.exists():
            raise FileNotFoundError(f"wintun.dll not found at {_DLL_PATH}")
        self.dll = ctypes.WinDLL(str(_DLL_PATH), use_last_error=True)

        d = self.dll

        d.WintunCreateAdapter.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.POINTER(GUID)]
        d.WintunCreateAdapter.restype = ctypes.c_void_p

        d.WintunOpenAdapter.argtypes = [wt.LPCWSTR]
        d.WintunOpenAdapter.restype = ctypes.c_void_p

        d.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
        d.WintunCloseAdapter.restype = None

        d.WintunGetAdapterLUID.argtypes = [ctypes.c_void_p, ctypes.POINTER(NET_LUID)]
        d.WintunGetAdapterLUID.restype = None

        d.WintunGetRunningDriverVersion.argtypes = []
        d.WintunGetRunningDriverVersion.restype = wt.DWORD

        d.WintunSetLogger.argtypes = [WINTUN_LOGGER_CALLBACK]
        d.WintunSetLogger.restype = None

        d.WintunStartSession.argtypes = [ctypes.c_void_p, wt.DWORD]
        d.WintunStartSession.restype = ctypes.c_void_p

        d.WintunEndSession.argtypes = [ctypes.c_void_p]
        d.WintunEndSession.restype = None

        d.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]
        d.WintunGetReadWaitEvent.restype = wt.HANDLE

        d.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
        d.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        d.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        d.WintunReleaseReceivePacket.restype = None

        d.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, wt.DWORD]
        d.WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        d.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        d.WintunSendPacket.restype = None


def set_logger(callback: Optional[Callable[[int, int, str], None]] = None):
    """Set a Python logger callback. Pass None to disable."""
    wt_ = _Wintun()
    if callback is None:
        wt_.dll.WintunSetLogger(WINTUN_LOGGER_CALLBACK(0))
        return None
    c_cb = WINTUN_LOGGER_CALLBACK(callback)
    wt_.dll.WintunSetLogger(c_cb)
    # Keep a reference so it isn't GC'd
    set_logger._cb = c_cb
    return c_cb


def driver_version() -> int:
    return _Wintun().dll.WintunGetRunningDriverVersion()


class Adapter:
    """Wintun adapter — represents a virtual network interface."""

    def __init__(self, name: str, tunnel_type: str = "WireGuard",
                 requested_guid: Optional[bytes] = None,
                 _existing_handle: Optional[int] = None):
        self._wt = _Wintun()
        self.name = name
        self.tunnel_type = tunnel_type
        if _existing_handle is not None:
            self._handle = _existing_handle
        else:
            guid_arg = None
            if requested_guid is not None:
                if len(requested_guid) != 16:
                    raise ValueError("requested_guid must be 16 bytes")
                g = GUID()
                ctypes.memmove(ctypes.byref(g), requested_guid, 16)
                guid_arg = ctypes.byref(g)
            self._handle = self._wt.dll.WintunCreateAdapter(name, tunnel_type, guid_arg)
            if not self._handle:
                raise WintunError(_last_error_str())

    @classmethod
    def open(cls, name: str) -> "Adapter":
        wt_ = _Wintun()
        handle = wt_.dll.WintunOpenAdapter(name)
        if not handle:
            raise WintunError(_last_error_str())
        a = cls.__new__(cls)
        a._wt = wt_
        a.name = name
        a.tunnel_type = ""
        a._handle = handle
        return a

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def luid(self) -> int:
        out = NET_LUID()
        self._wt.dll.WintunGetAdapterLUID(self._handle, ctypes.byref(out))
        return out.Value

    def start_session(self, capacity: int = DEFAULT_RING_CAPACITY) -> "Session":
        if not (WINTUN_MIN_RING_CAPACITY <= capacity <= WINTUN_MAX_RING_CAPACITY):
            raise ValueError("ring capacity out of range")
        if capacity & (capacity - 1):
            raise ValueError("ring capacity must be a power of two")
        h = self._wt.dll.WintunStartSession(self._handle, capacity)
        if not h:
            raise WintunError(_last_error_str())
        return Session(self, h)

    def close(self) -> None:
        if self._handle:
            self._wt.dll.WintunCloseAdapter(self._handle)
            self._handle = None

    def __enter__(self) -> "Adapter":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class Session:
    """Active Wintun session. Use receive_packet() / send_packet()."""

    def __init__(self, adapter: Adapter, handle: int):
        self._wt = adapter._wt
        self._adapter = adapter
        self._handle = handle
        self._closed = False

    @property
    def read_wait_event(self) -> int:
        return self._wt.dll.WintunGetReadWaitEvent(self._handle)

    def receive_packet(self, wait_ms: int = INFINITE) -> Optional[bytes]:
        """Receive a packet. Returns bytes or None on timeout/EOF.

        Blocks on the read wait event when no packet is immediately available.
        """
        size = wt.DWORD(0)
        ptr = self._wt.dll.WintunReceivePacket(self._handle, ctypes.byref(size))
        if ptr:
            try:
                return bytes(ctypes.string_at(ptr, size.value))
            finally:
                self._wt.dll.WintunReleaseReceivePacket(self._handle, ptr)
        err = ctypes.get_last_error()
        if err == ERROR_NO_MORE_ITEMS:
            if wait_ms == 0:
                return None
            ev = self.read_wait_event
            rc = _WaitForSingleObject(ev, wait_ms)
            if rc != WAIT_OBJECT_0:
                return None
            # Retry once
            size = wt.DWORD(0)
            ptr = self._wt.dll.WintunReceivePacket(self._handle, ctypes.byref(size))
            if ptr:
                try:
                    return bytes(ctypes.string_at(ptr, size.value))
                finally:
                    self._wt.dll.WintunReleaseReceivePacket(self._handle, ptr)
            return None
        if err == ERROR_HANDLE_EOF:
            return None
        raise WintunError(_last_error_str())

    def send_packet(self, packet: bytes) -> None:
        size = len(packet)
        if size == 0 or size > WINTUN_MAX_IP_PACKET_SIZE:
            raise ValueError("packet size out of range")
        ptr = self._wt.dll.WintunAllocateSendPacket(self._handle, size)
        if not ptr:
            raise WintunError(_last_error_str())
        ctypes.memmove(ptr, packet, size)
        self._wt.dll.WintunSendPacket(self._handle, ptr)

    def close(self) -> None:
        if not self._closed:
            self._wt.dll.WintunEndSession(self._handle)
            self._closed = True
            self._handle = None

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
