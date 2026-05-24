"""Tests for settings.py and monitor logic.

Monitor is tested with a fake wgapi (no real tunnel).
"""
import os
import sys
import time
import json
import tempfile
import shutil
import threading
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import settings as S
import monitor as M


def _reset_settings(tmp: Path):
    S.SETTINGS_PATH = tmp / "settings.json"
    S.SETTINGS_DIR = tmp
    S._cache = None


def test_settings_round_trip():
    tmp = Path(tempfile.mkdtemp(prefix="lwg_s_"))
    try:
        _reset_settings(tmp)
        s = S.load()
        assert s.auto_reconnect.enabled is False
        s.auto_reconnect.enabled = True
        s.auto_reconnect.min_kbps = 200
        s.auto_reconnect.window_sec = 15
        s.auto_reconnect.delay_sec = 8
        S.save(s)
        # Reload from disk
        S._cache = None
        s2 = S.load()
        assert s2.auto_reconnect.enabled is True
        assert s2.auto_reconnect.min_kbps == 200
        assert s2.auto_reconnect.window_sec == 15
        assert s2.auto_reconnect.delay_sec == 8
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_per_tunnel_override():
    tmp = Path(tempfile.mkdtemp(prefix="lwg_s_"))
    try:
        _reset_settings(tmp)
        s = S.load()
        s.auto_reconnect.min_kbps = 50
        S.save(s)
        S.set_auto_reconnect_per_tunnel("alpha", S.AutoReconnect(
            enabled=True, min_kbps=300, window_sec=20, delay_sec=5,
        ))
        eff = S.get_auto_reconnect_for("alpha")
        assert eff.min_kbps == 300
        assert eff.enabled is True
        eff_other = S.get_auto_reconnect_for("beta")
        assert eff_other.min_kbps == 50
        # Remove override
        S.set_auto_reconnect_per_tunnel("alpha", None)
        eff = S.get_auto_reconnect_for("alpha")
        assert eff.min_kbps == 50
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_monitor_triggers_reconnect_under_threshold(monkeypatch=None):
    """Drive monitor with fake wgapi.get_stats producing slow traffic."""
    triggered = threading.Event()
    reconnects = []

    fake_state = {
        "active": True,
        "rx_total": 0,  # bytes; we'll grow it slowly to simulate ~1 KB/s
        "deactivated": False,
        "activated_again": False,
    }
    rx_lock = threading.Lock()

    def fake_is_active(name):
        return fake_state["active"]

    def fake_get_stats(name):
        with rx_lock:
            return {
                "rx_bytes": fake_state["rx_total"],
                "tx_bytes": 0,
                "last_handshake": int(time.time()),
                "endpoint": "1.2.3.4:51820",
            }

    def fake_deactivate(name):
        fake_state["deactivated"] = True
        fake_state["active"] = False
        return True, "ok"

    def fake_activate(name):
        fake_state["activated_again"] = True
        fake_state["active"] = True
        return True, "ok"

    import wgapi
    orig_is_active = wgapi.is_active
    orig_get_stats = wgapi.get_stats
    orig_deactivate = wgapi.deactivate
    orig_activate = wgapi.activate
    wgapi.is_active = fake_is_active
    wgapi.get_stats = fake_get_stats
    wgapi.deactivate = fake_deactivate
    wgapi.activate = fake_activate

    def cb(evt, info):
        reconnects.append((evt, info))
        if evt == "reconnect_done":
            triggered.set()

    try:
        # 100 KB/s threshold; window 3s; delay 1s
        ar = S.AutoReconnect(enabled=True, min_kbps=100, window_sec=3, delay_sec=1)
        mon = M.AutoReconnectMonitor("alpha", callback=cb,
                                      settings_provider=lambda: ar)
        # Slow traffic: 1 KB/s — well below threshold
        def grow():
            for _ in range(20):
                with rx_lock:
                    fake_state["rx_total"] += 1024  # +1 KB/s
                time.sleep(1.0)
        producer = threading.Thread(target=grow, daemon=True)
        producer.start()
        mon.start()

        ok = triggered.wait(timeout=20)
        mon.stop()
        mon.join(timeout=5)
        assert ok, f"reconnect did not fire. events={reconnects}"
        assert fake_state["deactivated"] and fake_state["activated_again"]
    finally:
        wgapi.is_active = orig_is_active
        wgapi.get_stats = orig_get_stats
        wgapi.deactivate = orig_deactivate
        wgapi.activate = orig_activate


def test_monitor_disabled_does_nothing():
    triggered = threading.Event()
    fake = {"rx_total": 0}

    def fake_is_active(_): return True
    def fake_get_stats(_):
        return {"rx_bytes": fake["rx_total"], "tx_bytes": 0,
                "last_handshake": int(time.time()), "endpoint": "x"}
    def fake_deactivate(_):
        triggered.set()
        return True, "ok"
    def fake_activate(_):
        return True, "ok"

    import wgapi
    orig = (wgapi.is_active, wgapi.get_stats, wgapi.deactivate, wgapi.activate)
    wgapi.is_active = fake_is_active
    wgapi.get_stats = fake_get_stats
    wgapi.deactivate = fake_deactivate
    wgapi.activate = fake_activate
    try:
        ar = S.AutoReconnect(enabled=False, min_kbps=100, window_sec=2, delay_sec=1)
        mon = M.AutoReconnectMonitor("alpha", settings_provider=lambda: ar)
        mon.start()
        # 5 seconds: nothing should trigger because disabled
        time.sleep(5)
        mon.stop()
        mon.join(timeout=3)
        assert not triggered.is_set()
    finally:
        wgapi.is_active, wgapi.get_stats, wgapi.deactivate, wgapi.activate = orig


def run_all():
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    failures = []
    for t in tests:
        name = t.__name__
        try:
            t()
            print(f"PASS  {name}")
        except AssertionError as e:
            failures.append((name, f"AssertionError: {e}"))
            print(f"FAIL  {name}: {e}")
        except Exception as e:
            failures.append((name, f"{type(e).__name__}: {e}"))
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(run_all())
