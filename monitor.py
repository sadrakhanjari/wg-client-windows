"""Speed monitor + auto-reconnect engine.

Watches the active tunnel's download-byte counter. If the average download
rate stays below the configured threshold for the configured window, it
disconnects, waits the configured delay, then reconnects.
"""
import time
import threading
from collections import deque
from typing import Callable, Optional

import wgapi
import settings as _settings


class AutoReconnectMonitor(threading.Thread):
    """Runs in the background while a tunnel is active.

    callback (optional) gets called on state changes:
        callback("reconnect_triggered", reason: str)
        callback("reconnect_done", "")
        callback("reconnect_failed", err: str)
    """

    def __init__(self, tunnel_name: str,
                 callback: Optional[Callable[[str, str], None]] = None,
                 settings_provider: Optional[Callable[[], "_settings.AutoReconnect"]] = None):
        super().__init__(daemon=True, name=f"auto-reconnect[{tunnel_name}]")
        self.tunnel_name = tunnel_name
        self.callback = callback
        self.settings_provider = settings_provider or (
            lambda: _settings.get_auto_reconnect_for(tunnel_name)
        )
        self._stop_evt = threading.Event()
        self._last_rx: Optional[int] = None
        self._last_ts: Optional[float] = None
        self._rates: deque[tuple[float, float]] = deque()  # (ts, kbps)

    def stop(self) -> None:
        self._stop_evt.set()

    def _notify(self, evt: str, info: str = "") -> None:
        if self.callback:
            try:
                self.callback(evt, info)
            except Exception:
                pass

    def _sample_rate(self) -> Optional[float]:
        """Return current RX rate in KB/s, or None if not measurable yet."""
        stats = wgapi.get_stats(self.tunnel_name)
        if not stats:
            return None
        rx = stats["rx_bytes"]
        now = time.time()
        if self._last_rx is None:
            self._last_rx = rx
            self._last_ts = now
            return None
        dt = max(now - (self._last_ts or now), 0.001)
        drx = max(rx - self._last_rx, 0)
        self._last_rx = rx
        self._last_ts = now
        return (drx / dt) / 1024.0  # bytes/s → KB/s

    def _avg_kbps_in_window(self, window_sec: int) -> Optional[float]:
        if not self._rates:
            return None
        cutoff = time.time() - window_sec
        vals = [v for ts, v in self._rates if ts >= cutoff]
        if not vals:
            return None
        return sum(vals) / len(vals)

    def _under_threshold_for_full_window(self, cfg) -> bool:
        if not self._rates:
            return False
        now = time.time()
        cutoff = now - cfg.window_sec
        # Need samples covering the full window
        oldest = self._rates[0][0]
        if oldest > cutoff:
            return False
        avg = self._avg_kbps_in_window(cfg.window_sec)
        return avg is not None and avg < cfg.min_kbps

    def run(self) -> None:
        # Wait a brief grace period after handshake before measuring
        time.sleep(2.0)
        while not self._stop_evt.is_set():
            cfg = self.settings_provider()
            if not cfg.enabled:
                time.sleep(2.0)
                continue
            if not wgapi.is_active(self.tunnel_name):
                # Tunnel went away — exit
                return
            rate = self._sample_rate()
            if rate is not None:
                self._rates.append((time.time(), rate))
                # Drop samples older than window
                cutoff = time.time() - cfg.window_sec - 2
                while self._rates and self._rates[0][0] < cutoff:
                    self._rates.popleft()

                if self._under_threshold_for_full_window(cfg):
                    self._notify(
                        "reconnect_triggered",
                        f"avg < {cfg.min_kbps} KB/s for {cfg.window_sec}s",
                    )
                    self._do_reconnect(cfg.delay_sec)
                    # Reset sampler so we start fresh after reconnect
                    self._last_rx = None
                    self._last_ts = None
                    self._rates.clear()
                    # Small breathing room before resuming monitoring
                    time.sleep(2.0)
            self._stop_evt.wait(1.0)

    def _do_reconnect(self, delay_sec: int) -> None:
        wgapi.deactivate(self.tunnel_name)
        # Sleep but remain responsive to stop
        if self._stop_evt.wait(max(delay_sec, 0)):
            return
        ok, msg = wgapi.activate(self.tunnel_name)
        if ok:
            self._notify("reconnect_done", "")
        else:
            self._notify("reconnect_failed", msg)
