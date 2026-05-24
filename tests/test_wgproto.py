"""Tests for wgproto.py — handshake round-trip and data plane."""
import os
import sys
import time
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wgproto as p


def test_kdf_outputs_are_distinct_and_32_bytes():
    out = p.kdf_n(b"\x01" * 32, b"hello", 3)
    assert len(out) == 3
    for o in out:
        assert len(o) == 32
    assert len(set(out)) == 3  # all distinct


def test_aead_round_trip():
    key = os.urandom(32)
    ct = p.aead_encrypt(key, 5, b"hello world", b"aad")
    pt = p.aead_decrypt(key, 5, ct, b"aad")
    assert pt == b"hello world"


def test_tai64n_length():
    ts = p.tai64n_now()
    assert len(ts) == 12


def test_handshake_round_trip_psk_zero():
    # Initiator
    init_priv = p.x25519_generate()
    init_pub = p.x25519_pub_bytes(init_priv)

    # Responder
    resp_priv = p.x25519_generate()
    resp_pub = p.x25519_pub_bytes(resp_priv)

    init_state = p.HandshakeState(
        static_private=init_priv, static_public=init_pub,
        peer_static_public=resp_pub,
    )

    # Initiator → message
    init_msg = p.build_initiation(init_state)
    assert len(init_msg) == p.MSG_INITIATION_SIZE
    assert struct.unpack("<I", init_msg[:4])[0] == p.MSG_INITIATION

    # Responder consumes
    info = p.consume_initiation(resp_priv, resp_pub, init_msg)
    assert info is not None, "responder failed to parse initiation"
    assert info["initiator_static"] == init_pub
    assert info["sender_index"] == init_state.local_index

    # Responder builds response
    responder_index = 0xDEADBEEF
    resp_msg, resp_send_key, resp_recv_key = p.build_response(
        resp_priv, resp_pub, init_pub, info, responder_index,
    )
    assert len(resp_msg) == p.MSG_RESPONSE_SIZE

    # Initiator consumes response
    ok = p.consume_response(init_state, resp_msg)
    assert ok, "initiator failed to consume response"

    # Verify keys match across the wire
    assert init_state.sending_key == resp_recv_key, "send/recv key mismatch (init→resp)"
    assert init_state.receiving_key == resp_send_key, "send/recv key mismatch (resp→init)"
    assert init_state.remote_index == responder_index


def test_handshake_round_trip_with_psk():
    psk = os.urandom(32)
    init_priv = p.x25519_generate()
    init_pub = p.x25519_pub_bytes(init_priv)
    resp_priv = p.x25519_generate()
    resp_pub = p.x25519_pub_bytes(resp_priv)

    init_state = p.HandshakeState(
        static_private=init_priv, static_public=init_pub,
        peer_static_public=resp_pub, preshared_key=psk,
    )
    init_msg = p.build_initiation(init_state)
    info = p.consume_initiation(resp_priv, resp_pub, init_msg)
    assert info is not None

    resp_msg, resp_send, resp_recv = p.build_response(
        resp_priv, resp_pub, init_pub, info, 12345, preshared_key=psk,
    )
    assert p.consume_response(init_state, resp_msg)
    assert init_state.sending_key == resp_recv
    assert init_state.receiving_key == resp_send


def test_handshake_psk_mismatch_fails():
    init_priv = p.x25519_generate()
    init_pub = p.x25519_pub_bytes(init_priv)
    resp_priv = p.x25519_generate()
    resp_pub = p.x25519_pub_bytes(resp_priv)

    init_state = p.HandshakeState(
        static_private=init_priv, static_public=init_pub,
        peer_static_public=resp_pub, preshared_key=os.urandom(32),
    )
    init_msg = p.build_initiation(init_state)
    info = p.consume_initiation(resp_priv, resp_pub, init_msg)
    assert info is not None
    # Responder uses different PSK
    resp_msg, _, _ = p.build_response(
        resp_priv, resp_pub, init_pub, info, 42, preshared_key=os.urandom(32),
    )
    assert not p.consume_response(init_state, resp_msg)


def _establish_handshake():
    init_priv = p.x25519_generate()
    resp_priv = p.x25519_generate()
    init_pub = p.x25519_pub_bytes(init_priv)
    resp_pub = p.x25519_pub_bytes(resp_priv)

    init_state = p.HandshakeState(
        static_private=init_priv, static_public=init_pub,
        peer_static_public=resp_pub,
    )
    resp_state = p.HandshakeState(
        static_private=resp_priv, static_public=resp_pub,
        peer_static_public=init_pub,
    )

    init_msg = p.build_initiation(init_state)
    info = p.consume_initiation(resp_priv, resp_pub, init_msg)
    resp_msg, resp_send, resp_recv = p.build_response(
        resp_priv, resp_pub, init_pub, info, 0xABCD1234,
    )
    assert p.consume_response(init_state, resp_msg)

    # Populate responder state to look like a real responder for transport tests
    resp_state.local_index = 0xABCD1234
    resp_state.remote_index = init_state.local_index
    resp_state.sending_key = resp_send
    resp_state.receiving_key = resp_recv

    return init_state, resp_state


def test_transport_round_trip():
    init_state, resp_state = _establish_handshake()
    payload = b"the quick brown fox jumps over the lazy dog"
    msg = p.build_transport(init_state, payload)
    rw = p.ReplayWindow()
    pt = p.consume_transport(resp_state, rw, msg)
    assert pt == payload


def test_transport_replay_blocked():
    init_state, resp_state = _establish_handshake()
    msg = p.build_transport(init_state, b"hello")
    rw = p.ReplayWindow()
    assert p.consume_transport(resp_state, rw, msg) == b"hello"
    assert p.consume_transport(resp_state, rw, msg) is None  # replay


def test_transport_out_of_order_within_window():
    init_state, resp_state = _establish_handshake()
    msgs = [p.build_transport(init_state, f"msg-{i}".encode()) for i in range(5)]
    rw = p.ReplayWindow()
    # Receive out of order: 2, 0, 4, 1, 3
    order = [2, 0, 4, 1, 3]
    received = []
    for i in order:
        pt = p.consume_transport(resp_state, rw, msgs[i])
        received.append((i, pt))
    for i, pt in received:
        assert pt == f"msg-{i}".encode()


def test_transport_far_past_blocked():
    init_state, resp_state = _establish_handshake()
    # Manually craft a packet with very large counter, then one with counter 0
    state2 = p.HandshakeState(
        static_private=init_state.static_private,
        static_public=init_state.static_public,
        peer_static_public=init_state.peer_static_public,
    )
    # We'll just use the existing state and bump counter
    init_state.send_counter = 5000
    far_future = p.build_transport(init_state, b"future")
    rw = p.ReplayWindow()
    assert p.consume_transport(resp_state, rw, far_future) == b"future"

    init_state.send_counter = 1  # well below window low end (5000 - 2048)
    very_old = p.build_transport(init_state, b"old")
    assert p.consume_transport(resp_state, rw, very_old) is None


def test_mac1_tamper_detected():
    init_state, _ = _establish_handshake()
    resp_priv = p.x25519_generate()
    resp_pub = p.x25519_pub_bytes(resp_priv)
    init_state.peer_static_public = resp_pub

    msg = p.build_initiation(init_state)
    # Flip a byte in mac1 (the 16 bytes before the final 16-byte mac2)
    tampered = bytearray(msg)
    tampered[120] ^= 0xFF
    info = p.consume_initiation(resp_priv, resp_pub, bytes(tampered))
    assert info is None


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
