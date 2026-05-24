"""Tests for tunnel.parse_config and wgapi storage layer."""
import os
import sys
import base64
import shutil
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tunnel
import wgproto


SAMPLE_CONF = """\
[Interface]
PrivateKey = {priv}
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1380

[Peer]
PublicKey = {pub}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"""


def _make_conf() -> str:
    priv = wgproto.x25519_generate()
    pub = wgproto.x25519_generate()
    return SAMPLE_CONF.format(
        priv=base64.b64encode(wgproto.x25519_priv_bytes(priv)).decode(),
        pub=base64.b64encode(wgproto.x25519_pub_bytes(pub)).decode(),
        psk=base64.b64encode(os.urandom(32)).decode(),
    )


def test_parse_basic():
    conf = _make_conf()
    cfg = tunnel.parse_config(conf, name="test")
    assert cfg.name == "test"
    assert len(cfg.private_key) == 32
    assert len(cfg.peer_public) == 32
    assert len(cfg.preshared_key) == 32
    assert cfg.address == ["10.0.0.2/32", "fd00::2/128"]
    assert cfg.dns == ["1.1.1.1", "8.8.8.8"]
    assert cfg.mtu == 1380
    assert cfg.peer_endpoint == ("vpn.example.com", 51820)
    assert cfg.allowed_ips == ["0.0.0.0/0", "::/0"]
    assert cfg.persistent_keepalive == 25


def test_parse_minimal():
    priv = base64.b64encode(wgproto.x25519_priv_bytes(wgproto.x25519_generate())).decode()
    pub = base64.b64encode(wgproto.x25519_pub_bytes(wgproto.x25519_generate())).decode()
    text = f"""\
[Interface]
PrivateKey = {priv}
Address = 10.0.0.2/24

[Peer]
PublicKey = {pub}
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
"""
    cfg = tunnel.parse_config(text)
    assert cfg.peer_endpoint == ("1.2.3.4", 51820)
    assert cfg.dns == []
    assert cfg.preshared_key == wgproto.ZERO_PSK
    assert cfg.persistent_keepalive == 0


def test_parse_ipv6_endpoint():
    priv = base64.b64encode(wgproto.x25519_priv_bytes(wgproto.x25519_generate())).decode()
    pub = base64.b64encode(wgproto.x25519_pub_bytes(wgproto.x25519_generate())).decode()
    text = f"""\
[Interface]
PrivateKey = {priv}
Address = 10.0.0.2/24

[Peer]
PublicKey = {pub}
AllowedIPs = 0.0.0.0/0
Endpoint = [2001:db8::1]:51820
"""
    cfg = tunnel.parse_config(text)
    assert cfg.peer_endpoint == ("2001:db8::1", 51820)


def test_parse_rejects_bad_privkey():
    text = """\
[Interface]
PrivateKey = invalid

[Peer]
PublicKey = invalid
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
"""
    try:
        tunnel.parse_config(text)
    except Exception:
        return
    raise AssertionError("expected parse failure for invalid PrivateKey base64")


def test_parse_ignores_comments():
    priv = base64.b64encode(wgproto.x25519_priv_bytes(wgproto.x25519_generate())).decode()
    pub = base64.b64encode(wgproto.x25519_pub_bytes(wgproto.x25519_generate())).decode()
    text = f"""\
# Top comment
[Interface]
# inline-ish
PrivateKey = {priv}  ; trailing? actually netshconf doesn't support trailing
Address = 10.0.0.2/24

[Peer]
PublicKey = {pub}
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
; semicolon comment
"""
    cfg = tunnel.parse_config(text)
    assert cfg.peer_endpoint == ("1.2.3.4", 51820)


def test_wgapi_storage_round_trip(monkeypatch=None):
    # Redirect CONF_DIR to a temp folder
    import wgapi as api
    tmp = Path(tempfile.mkdtemp(prefix="lwg_test_"))
    try:
        api.CONF_DIR = tmp
        conf = _make_conf()
        ok, msg = api.add_tunnel("alpha", conf)
        assert ok, msg
        assert (tmp / "alpha.conf").exists()
        lst = api.list_tunnels()
        assert any(t["name"] == "alpha" for t in lst)
        assert api.read_tunnel_config("alpha") == conf
        # Update
        new_conf = conf.replace("MTU = 1380", "MTU = 1280")
        ok, msg = api.update_tunnel("alpha", new_conf)
        assert ok, msg
        assert "1280" in api.read_tunnel_config("alpha")
        # Delete
        ok, msg = api.delete_tunnel("alpha")
        assert ok, msg
        assert not (tmp / "alpha.conf").exists()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_wgapi_rejects_invalid_name():
    import wgapi as api
    tmp = Path(tempfile.mkdtemp(prefix="lwg_test_"))
    try:
        api.CONF_DIR = tmp
        ok, msg = api.add_tunnel("../evil", _make_conf())
        assert not ok
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_all():
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
    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(run_all())
