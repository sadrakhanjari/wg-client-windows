"""WireGuard protocol: Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s.

Phase 1: Handshake (initiation + response consumption).
Phase 2: Data plane (transport encrypt/decrypt) + replay window + timers.

References:
- WireGuard whitepaper: https://www.wireguard.com/papers/wireguard.pdf
- wireguard-go reference implementation
"""
import os
import hmac
import time
import struct
import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ---- Constants from WireGuard whitepaper ----
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

INITIAL_CHAINING_KEY = hashlib.blake2s(CONSTRUCTION).digest()
INITIAL_HASH = hashlib.blake2s(INITIAL_CHAINING_KEY + IDENTIFIER).digest()

# Message types
MSG_INITIATION = 1
MSG_RESPONSE = 2
MSG_COOKIE = 3
MSG_TRANSPORT = 4

# Sizes
MSG_INITIATION_SIZE = 148
MSG_RESPONSE_SIZE = 92
MSG_COOKIE_SIZE = 64
MSG_TRANSPORT_HEADER_SIZE = 16  # type(4) + receiver(4) + counter(8)
AEAD_TAG_SIZE = 16

ZERO_PSK = b"\x00" * 32


# ---- BLAKE2s + HMAC + HKDF ----
def blake2s(*chunks: bytes) -> bytes:
    h = hashlib.blake2s()
    for c in chunks:
        h.update(c)
    return h.digest()  # 32 bytes


def blake2s_mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.blake2s).digest()  # 32 bytes


def hash_chain(h: bytes, data: bytes) -> bytes:
    return blake2s(h, data)


def kdf_n(key: bytes, input_: bytes, n: int) -> list[bytes]:
    """WireGuard's HKDF using HMAC-BLAKE2s. Returns n 32-byte outputs.

    τ₀ = HMAC(key, input)
    τ₁ = HMAC(τ₀, 0x01)
    τ₂ = HMAC(τ₀, τ₁ || 0x02)
    τ₃ = HMAC(τ₀, τ₂ || 0x03)
    """
    t0 = hmac_blake2s(key, input_)
    out = []
    prev = b""
    for i in range(1, n + 1):
        prev = hmac_blake2s(t0, prev + bytes([i]))
        out.append(prev)
    return out


# ---- X25519 ----
def x25519_generate() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def x25519_priv_from_bytes(b: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(b)


def x25519_pub_from_bytes(b: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(b)


def x25519_pub_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def x25519_priv_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def dh(priv: X25519PrivateKey, pub_bytes: bytes) -> bytes:
    return priv.exchange(x25519_pub_from_bytes(pub_bytes))


# ---- AEAD (ChaCha20Poly1305) ----
def aead_nonce(counter: int) -> bytes:
    # 96-bit nonce: 4 bytes zero || 8 bytes counter (LE)
    return b"\x00\x00\x00\x00" + struct.pack("<Q", counter)


def aead_encrypt(key: bytes, counter: int, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(aead_nonce(counter), plaintext, aad)


def aead_decrypt(key: bytes, counter: int, ciphertext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(aead_nonce(counter), ciphertext, aad)


# ---- TAI64N timestamp ----
def tai64n_now() -> bytes:
    # 8 bytes seconds (TAI64) + 4 bytes nanoseconds, big-endian.
    # TAI64 = 2^62 + (TAI seconds since 1970). We approximate TAI - UTC = 37s.
    now = time.time()
    secs = int(now) + 0x4000000000000000 + 37
    nsec = int((now - int(now)) * 1_000_000_000)
    return struct.pack(">QI", secs, nsec)


# ---- MAC1 / MAC2 ----
def mac1_key_for(responder_static_pub: bytes) -> bytes:
    return blake2s(LABEL_MAC1, responder_static_pub)


def compute_mac(key: bytes, msg: bytes) -> bytes:
    return blake2s_mac(key, msg)


# ---- Replay window (sliding 2048-bit) ----
class ReplayWindow:
    """Sliding-window replay protection. Window size matches WireGuard's 2048."""
    WINDOW_SIZE = 2048
    BITMAP_WORDS = WINDOW_SIZE // 64

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._highest = 0
        self._bitmap = [0] * self.BITMAP_WORDS

    def check_and_set(self, counter: int) -> bool:
        with self._lock:
            if counter > self._highest:
                diff = counter - self._highest
                if diff >= self.WINDOW_SIZE:
                    self._bitmap = [0] * self.BITMAP_WORDS
                else:
                    self._shift_left(diff)
                self._highest = counter
                self._set_bit(0)
                return True
            offset = self._highest - counter
            if offset >= self.WINDOW_SIZE:
                return False
            if self._get_bit(offset):
                return False
            self._set_bit(offset)
            return True

    def _set_bit(self, offset_from_top: int) -> None:
        word = offset_from_top // 64
        bit = offset_from_top % 64
        self._bitmap[word] |= (1 << bit)

    def _get_bit(self, offset_from_top: int) -> bool:
        word = offset_from_top // 64
        bit = offset_from_top % 64
        return bool(self._bitmap[word] & (1 << bit))

    def _shift_left(self, n: int) -> None:
        if n <= 0:
            return
        if n >= self.WINDOW_SIZE:
            self._bitmap = [0] * self.BITMAP_WORDS
            return
        word_shift, bit_shift = divmod(n, 64)
        new = [0] * self.BITMAP_WORDS
        for i in range(self.BITMAP_WORDS - 1, -1, -1):
            src = i - word_shift
            if src < 0:
                continue
            v = self._bitmap[src] << bit_shift
            if bit_shift and src - 1 >= 0:
                v |= (self._bitmap[src - 1] >> (64 - bit_shift))
            new[i] = v & 0xFFFFFFFFFFFFFFFF
        self._bitmap = new


# ---- Handshake state ----
@dataclass
class HandshakeState:
    static_private: X25519PrivateKey
    static_public: bytes
    peer_static_public: bytes
    preshared_key: bytes = field(default=ZERO_PSK)

    chaining_key: bytes = b""
    hash: bytes = b""
    ephemeral_private: Optional[X25519PrivateKey] = None
    ephemeral_public: bytes = b""

    local_index: int = 0
    remote_index: int = 0

    # Filled after a successful handshake
    sending_key: bytes = b""
    receiving_key: bytes = b""
    send_counter: int = 0
    established_at: float = 0.0


# ---- Handshake: Initiator ----
def build_initiation(state: HandshakeState, local_index: Optional[int] = None) -> bytes:
    state.chaining_key = INITIAL_CHAINING_KEY
    state.hash = hash_chain(INITIAL_HASH, state.peer_static_public)

    state.ephemeral_private = x25519_generate()
    state.ephemeral_public = x25519_pub_bytes(state.ephemeral_private)

    state.local_index = (
        local_index if local_index is not None
        else int.from_bytes(secrets.token_bytes(4), "little")
    )

    state.chaining_key = kdf_n(state.chaining_key, state.ephemeral_public, 1)[0]
    state.hash = hash_chain(state.hash, state.ephemeral_public)

    dh_es = dh(state.ephemeral_private, state.peer_static_public)
    state.chaining_key, k = kdf_n(state.chaining_key, dh_es, 2)
    enc_static = aead_encrypt(k, 0, state.static_public, state.hash)
    state.hash = hash_chain(state.hash, enc_static)

    dh_ss = dh(state.static_private, state.peer_static_public)
    state.chaining_key, k = kdf_n(state.chaining_key, dh_ss, 2)
    enc_ts = aead_encrypt(k, 0, tai64n_now(), state.hash)
    state.hash = hash_chain(state.hash, enc_ts)

    # Assemble message up to MAC1 offset
    msg = b""
    msg += struct.pack("<I", MSG_INITIATION)
    msg += struct.pack("<I", state.local_index)
    msg += state.ephemeral_public
    msg += enc_static
    msg += enc_ts
    assert len(msg) == 4 + 4 + 32 + 48 + 28, f"unexpected pre-mac size {len(msg)}"

    mac1 = compute_mac(mac1_key_for(state.peer_static_public), msg)
    msg += mac1
    msg += b"\x00" * 16  # mac2: zero when no cookie

    assert len(msg) == MSG_INITIATION_SIZE
    return msg


def consume_response(state: HandshakeState, msg: bytes) -> bool:
    """Process incoming response message; returns True iff valid."""
    if len(msg) != MSG_RESPONSE_SIZE:
        return False
    msg_type, = struct.unpack("<I", msg[0:4])
    if msg_type != MSG_RESPONSE:
        return False

    sender_index, = struct.unpack("<I", msg[4:8])
    receiver_index, = struct.unpack("<I", msg[8:12])
    if receiver_index != state.local_index:
        return False

    eph_pub = msg[12:44]
    enc_empty = msg[44:60]

    # MAC1 check
    expected_mac1 = compute_mac(mac1_key_for(state.static_public), msg[:60])
    if expected_mac1 != msg[60:76]:
        return False

    chaining_key = state.chaining_key
    h = state.hash

    chaining_key = kdf_n(chaining_key, eph_pub, 1)[0]
    h = hash_chain(h, eph_pub)

    dh_ee = dh(state.ephemeral_private, eph_pub)
    chaining_key = kdf_n(chaining_key, dh_ee, 1)[0]

    dh_se = dh(state.static_private, eph_pub)
    chaining_key = kdf_n(chaining_key, dh_se, 1)[0]

    chaining_key, t, k = kdf_n(chaining_key, state.preshared_key, 3)
    h = hash_chain(h, t)

    try:
        empty = aead_decrypt(k, 0, enc_empty, h)
    except Exception:
        return False
    if empty != b"":
        return False

    h = hash_chain(h, enc_empty)

    # Commit state
    state.chaining_key = chaining_key
    state.hash = h
    state.remote_index = sender_index

    send, recv = kdf_n(state.chaining_key, b"", 2)
    state.sending_key = send
    state.receiving_key = recv
    state.send_counter = 0
    state.established_at = time.time()
    return True


# ---- Handshake: Responder (used for self-test; we don't act as server in client) ----
def consume_initiation(
    responder_static_private: X25519PrivateKey,
    responder_static_public: bytes,
    msg: bytes,
) -> Optional[dict]:
    """Process initiation. Returns dict with extracted info, or None on failure."""
    if len(msg) != MSG_INITIATION_SIZE:
        return None
    if struct.unpack("<I", msg[0:4])[0] != MSG_INITIATION:
        return None

    sender_index, = struct.unpack("<I", msg[4:8])
    eph_pub = msg[8:40]
    enc_static = msg[40:88]
    enc_ts = msg[88:116]
    mac1 = msg[116:132]

    expected_mac1 = compute_mac(mac1_key_for(responder_static_public), msg[:116])
    if expected_mac1 != mac1:
        return None

    chaining_key = INITIAL_CHAINING_KEY
    h = hash_chain(INITIAL_HASH, responder_static_public)

    chaining_key = kdf_n(chaining_key, eph_pub, 1)[0]
    h = hash_chain(h, eph_pub)

    dh_es = dh(responder_static_private, eph_pub)
    chaining_key, k = kdf_n(chaining_key, dh_es, 2)
    try:
        initiator_static = aead_decrypt(k, 0, enc_static, h)
    except Exception:
        return None
    h = hash_chain(h, enc_static)

    dh_ss = dh(responder_static_private, initiator_static)
    chaining_key, k = kdf_n(chaining_key, dh_ss, 2)
    try:
        timestamp = aead_decrypt(k, 0, enc_ts, h)
    except Exception:
        return None
    h = hash_chain(h, enc_ts)

    return {
        "sender_index": sender_index,
        "ephemeral_public": eph_pub,
        "initiator_static": initiator_static,
        "timestamp": timestamp,
        "chaining_key": chaining_key,
        "hash": h,
    }


def build_response(
    responder_static_private: X25519PrivateKey,
    responder_static_public: bytes,
    initiator_static_public: bytes,
    init_state: dict,
    responder_local_index: int,
    preshared_key: bytes = ZERO_PSK,
) -> tuple[bytes, bytes, bytes]:
    """Build response message. Returns (msg, sending_key, receiving_key) for responder."""
    chaining_key = init_state["chaining_key"]
    h = init_state["hash"]
    initiator_eph_pub = init_state["ephemeral_public"]

    eph_priv = x25519_generate()
    eph_pub = x25519_pub_bytes(eph_priv)

    chaining_key = kdf_n(chaining_key, eph_pub, 1)[0]
    h = hash_chain(h, eph_pub)

    dh_ee = dh(eph_priv, initiator_eph_pub)
    chaining_key = kdf_n(chaining_key, dh_ee, 1)[0]

    dh_se = dh(eph_priv, initiator_static_public)
    chaining_key = kdf_n(chaining_key, dh_se, 1)[0]

    chaining_key, t, k = kdf_n(chaining_key, preshared_key, 3)
    h = hash_chain(h, t)

    enc_empty = aead_encrypt(k, 0, b"", h)
    h = hash_chain(h, enc_empty)

    msg = b""
    msg += struct.pack("<I", MSG_RESPONSE)
    msg += struct.pack("<I", responder_local_index)
    msg += struct.pack("<I", init_state["sender_index"])
    msg += eph_pub
    msg += enc_empty
    mac1 = compute_mac(mac1_key_for(initiator_static_public), msg)
    msg += mac1
    msg += b"\x00" * 16

    assert len(msg) == MSG_RESPONSE_SIZE

    # Responder transport keys (note swap vs initiator)
    recv, send = kdf_n(chaining_key, b"", 2)
    return msg, send, recv


# ---- Data plane (Phase 2) ----
def build_transport(state: HandshakeState, plaintext: bytes) -> bytes:
    """Encrypt and frame an outgoing data packet."""
    counter = state.send_counter
    state.send_counter += 1
    enc = aead_encrypt(state.sending_key, counter, plaintext, b"")
    out = struct.pack("<I", MSG_TRANSPORT)
    out += struct.pack("<I", state.remote_index)
    out += struct.pack("<Q", counter)
    out += enc
    return out


def consume_transport(state: HandshakeState, replay: ReplayWindow, msg: bytes) -> Optional[bytes]:
    """Decrypt and validate an incoming data packet. Returns plaintext or None."""
    if len(msg) < MSG_TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE:
        return None
    if struct.unpack("<I", msg[0:4])[0] != MSG_TRANSPORT:
        return None
    receiver_index, = struct.unpack("<I", msg[4:8])
    if receiver_index != state.local_index:
        return None
    counter, = struct.unpack("<Q", msg[8:16])
    ciphertext = msg[16:]
    try:
        plaintext = aead_decrypt(state.receiving_key, counter, ciphertext, b"")
    except Exception:
        return None
    if not replay.check_and_set(counter):
        return None
    return plaintext


# ---- Timers / state ----
# WireGuard standard timer values (seconds)
REKEY_AFTER_MESSAGES = (1 << 60)
REJECT_AFTER_MESSAGES = (1 << 64) - (1 << 13) - 1
REKEY_AFTER_TIME = 120
REJECT_AFTER_TIME = 180
REKEY_ATTEMPT_TIME = 90
REKEY_TIMEOUT = 5
KEEPALIVE_TIMEOUT = 10
