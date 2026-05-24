"""End-to-end UDP integration: wgproto over real localhost sockets.

Validates that the protocol layer works correctly when packets actually
travel through a UDP socket (catches any byte-order/framing bugs not
exercised by the in-process round-trip in test_wgproto).
"""
import os
import sys
import time
import socket
import struct
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wgproto as p


class _Responder(threading.Thread):
    """Tiny WG-protocol UDP responder for testing."""

    def __init__(self, static_priv, static_pub):
        super().__init__(daemon=True)
        self.priv = static_priv
        self.pub = static_pub
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop_evt = threading.Event()
        self.send_key = b""
        self.recv_key = b""
        self.local_index = 0xCAFEF00D
        self.remote_index = 0
        self.replay = p.ReplayWindow()
        self.received_packets: list[bytes] = []

    def stop(self):
        self._stop_evt.set()
        try:
            self.sock.close()
        except Exception:
            pass

    def run(self):
        peer_addr = None
        while not self._stop_evt.is_set():
            try:
                self.sock.settimeout(0.5)
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            if not data:
                continue
            msg_type = data[0]
            if msg_type == p.MSG_INITIATION:
                info = p.consume_initiation(self.priv, self.pub, data)
                if info is None:
                    continue
                resp, send, recv = p.build_response(
                    self.priv, self.pub, info["initiator_static"],
                    info, self.local_index,
                )
                self.send_key = send
                self.recv_key = recv
                self.remote_index = info["sender_index"]
                self.sock.sendto(resp, addr)
                peer_addr = addr
            elif msg_type == p.MSG_TRANSPORT and self.recv_key:
                # Decrypt manually for testing
                receiver_idx, = struct.unpack("<I", data[4:8])
                if receiver_idx != self.local_index:
                    continue
                counter, = struct.unpack("<Q", data[8:16])
                try:
                    pt = p.aead_decrypt(self.recv_key, counter, data[16:], b"")
                except Exception:
                    continue
                if not self.replay.check_and_set(counter):
                    continue
                self.received_packets.append(pt)
                # Echo back
                if peer_addr and self.send_key:
                    counter_out = len(self.received_packets) - 1
                    enc = p.aead_encrypt(self.send_key, counter_out, pt[::-1], b"")
                    out = struct.pack("<I", p.MSG_TRANSPORT)
                    out += struct.pack("<I", self.remote_index)
                    out += struct.pack("<Q", counter_out)
                    out += enc
                    self.sock.sendto(out, peer_addr)


def test_udp_handshake_and_transport():
    resp_priv = p.x25519_generate()
    resp_pub = p.x25519_pub_bytes(resp_priv)
    init_priv = p.x25519_generate()
    init_pub = p.x25519_pub_bytes(init_priv)

    responder = _Responder(resp_priv, resp_pub)
    responder.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(2.0)
    try:
        state = p.HandshakeState(
            static_private=init_priv, static_public=init_pub,
            peer_static_public=resp_pub,
        )
        init_msg = p.build_initiation(state)
        sock.sendto(init_msg, ("127.0.0.1", responder.port))
        data, _ = sock.recvfrom(2048)
        assert p.consume_response(state, data), "response failed"

        # Send 3 transport packets
        client_replay = p.ReplayWindow()
        payloads = [b"alpha", b"bravo", b"charlie"]
        for pl in payloads:
            msg = p.build_transport(state, pl)
            sock.sendto(msg, ("127.0.0.1", responder.port))
            # Receive echo (reversed)
            data, _ = sock.recvfrom(2048)
            assert data[0] == p.MSG_TRANSPORT
            receiver_idx, = struct.unpack("<I", data[4:8])
            assert receiver_idx == state.local_index
            counter, = struct.unpack("<Q", data[8:16])
            pt = p.aead_decrypt(state.receiving_key, counter, data[16:], b"")
            assert pt == pl[::-1]
            assert client_replay.check_and_set(counter)

        # Allow a moment for server to register all
        deadline = time.time() + 2
        while len(responder.received_packets) < 3 and time.time() < deadline:
            time.sleep(0.05)
        assert responder.received_packets == payloads
    finally:
        sock.close()
        responder.stop()
        responder.join(timeout=2)


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
            traceback.print_exc()
        except Exception as e:
            failures.append((name, f"{type(e).__name__}: {e}"))
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(run_all())
