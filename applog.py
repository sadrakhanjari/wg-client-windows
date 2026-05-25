"""Shared file logger so we can trace exactly where activation gets stuck.

Log file: %LOCALAPPDATA%\\LocalWireGuard\\app.log
"""
import os
import logging
from pathlib import Path


_LOG_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LocalWireGuard"
_LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = _LOG_DIR / "app.log"


def get(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if not getattr(log, "_lwg_inited", False):
        # INFO by default: keeps connect/handshake/route/DNS trace but skips the
        # per-packet DEBUG logging that would do file I/O on the data hot path.
        # Set LWG_DEBUG=1 to restore full per-packet tracing for diagnosis.
        log.setLevel(logging.DEBUG if os.environ.get("LWG_DEBUG") else logging.INFO)
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        log.addHandler(fh)
        log._lwg_inited = True  # type: ignore[attr-defined]
    return log
