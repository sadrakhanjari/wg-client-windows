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
        log.setLevel(logging.DEBUG)
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        log.addHandler(fh)
        log._lwg_inited = True  # type: ignore[attr-defined]
    return log
