"""Tests for wintun.py. Adapter creation requires admin."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wintun


def test_dll_loads():
    """Loading the DLL should not require admin."""
    _ = wintun._Wintun()
    print(f"  driver_version={wintun.driver_version():#x}")


def test_adapter_lifecycle_admin_required():
    if not wintun.is_admin():
        print("  SKIP: not running as admin")
        return
    name = "LWG-Test"
    a = wintun.Adapter(name, "WireGuard-Test")
    try:
        print(f"  adapter handle={a.handle}, luid={a.luid:#x}")
        with a.start_session(wintun.DEFAULT_RING_CAPACITY) as sess:
            print(f"  session handle={sess._handle}")
            # Read with short timeout — should return None (no traffic)
            pkt = sess.receive_packet(wait_ms=200)
            print(f"  receive within 200ms: {pkt!r}")
    finally:
        a.close()
        print("  adapter closed")


def test_send_dummy_packet_admin_required():
    """Send a minimal IPv4 packet to ourselves through the adapter."""
    if not wintun.is_admin():
        print("  SKIP: not running as admin")
        return
    name = "LWG-Test2"
    with wintun.Adapter(name, "WireGuard-Test") as a:
        with a.start_session() as sess:
            # IPv4 header (20 bytes) + UDP (8 bytes) + 4 bytes payload
            # Minimal valid IPv4 packet: src 10.0.0.1 -> dst 10.0.0.2
            pkt = bytes.fromhex(
                "45000020" "00010000" "40110000"  # version/IHL, total len 32, ttl 64, proto UDP
                "0a000001" "0a000002"            # 10.0.0.1 -> 10.0.0.2
                "1f901f90" "000c0000"            # ports 8080->8080, len 12, csum 0
                "deadbeef"                       # payload
            )
            sess.send_packet(pkt)
            print(f"  sent {len(pkt)} bytes")


def run_all():
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    failures = []
    for t in tests:
        print(f"\n{t.__name__}:")
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception as e:
            failures.append((t.__name__, e))
            print(f"FAIL  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(run_all())
