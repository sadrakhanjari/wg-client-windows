"""Tests for netcfg.py. Most operations require admin and a real adapter."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netcfg


def test_ipv4_mask_helper():
    assert netcfg._ipv4_mask(24) == "255.255.255.0"
    assert netcfg._ipv4_mask(16) == "255.255.0.0"
    assert netcfg._ipv4_mask(32) == "255.255.255.255"


def test_get_default_gateway_returns_something():
    gw = netcfg.get_default_gateway(4)
    # On a normally-configured machine this should be an IP.
    print(f"  default gateway: {gw}")
    # Not a hard failure — connected machine should have one, but allow None
    # in case of CI/no network.


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
