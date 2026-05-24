"""Single-peer WireGuard tunnel: orchestrates handshake, UDP, Wintun, routing.

A Tunnel owns:
- a Wintun adapter + session (TUN device)
- a UDP socket (the WG transport)
- a HandshakeState (cryptographic state with the peer)
- IO threads (TUN→UDP and UDP→TUN)
- a timer thread (rekey detection, keepalive)

Public API is intentionally tiny:
    t = Tunnel(config)
    t.start()      # blocks until handshake completes; raises on failure
    t.stats        # property: dict of rx/tx/handshake_age/endpoint
    t.stop()       # tears everything down
"""
import base64
import ipaddress
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import netcfg
import wgproto
import wintun


@dataclass
class TunnelConfig:
    name: str
    private_key: bytes
    address: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    mtu: int = 1420
    peer_public: bytes = b""
    peer_endpoint: tuple[str, int] = ("", 0)
    preshared_key: bytes = wgproto.ZERO_PSK
    allowed_ips: list[str] = field(default_factory=list)
    persistent_keepalive: int = 0


def parse_config(text: str, name: str = "") -> TunnelConfig:
    """Parse a WireGuard .conf file (single Peer section)."""
    iface: dict = {}
    peer: dict = {}
    current = None
    multi_keys = {"Address", "DNS", "AllowedIPs"}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        if "=" not in line or current is None:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        target = iface if current == "Interface" else peer
        if key in multi_keys:
            target.setdefault(key, []).extend(v.strip() for v in val.split(",") if v.strip())
        else:
            target[key] = val

    if "PrivateKey" not in iface:
        raise ValueError("Interface section missing PrivateKey")
    if "PublicKey" not in peer or "Endpoint" not in peer:
        raise ValueError("Peer section missing PublicKey or Endpoint")

    priv = base64.b64decode(iface["PrivateKey"])
    if len(priv) != 32:
        raise ValueError("PrivateKey not 32 bytes after base64 decode")
    pub = base64.b64decode(peer["PublicKey"])
    if len(pub) != 32:
        raise ValueError("PublicKey not 32 bytes after base64 decode")
    psk = wgproto.ZERO_PSK
    if peer.get("PresharedKey"):
        psk = base64.b64decode(peer["PresharedKey"])
        if len(psk) != 32:
            raise ValueError("PresharedKey not 32 bytes after base64 decode")

    endpoint_str = peer["Endpoint"]
    if endpoint_str.startswith("["):  # IPv6 literal
        host, _, port = endpoint_str[1:].partition("]:")
    else:
        host, _, port = endpoint_str.rpartition(":")
    if not host or not port:
        raise ValueError(f"Invalid Endpoint: {endpoint_str}")

    return TunnelConfig(
        name=name,
        private_key=priv,
        address=iface.get("Address", []),
        dns=iface.get("DNS", []),
        mtu=int(iface.get("MTU", 1420)),
        peer_public=pub,
        peer_endpoint=(host, int(port)),
        preshared_key=psk,
        allowed_ips=peer.get("AllowedIPs", []),
        persistent_keepalive=int(peer.get("PersistentKeepalive", 0)),
    )


class Tunnel:
    HANDSHAKE_TIMEOUT = 5.0
    HANDSHAKE_ATTEMPTS = 3

    def __init__(self, config: TunnelConfig):
        self.config = config
        self._adapter: Optional[wintun.Adapter] = None
        self._session: Optional[wintun.Session] = None
        self._udp: Optional[socket.socket] = None
        self._state: Optional[wgproto.HandshakeState] = None
        self._replay = wgproto.ReplayWindow()
        self._endpoint: tuple[str, int] = ("", 0)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._added_routes: list[str] = []
        self._endpoint_route_added: Optional[str] = None

        self._lock = threading.Lock()
        self._rx = 0
        self._tx = 0
        self._last_handshake_at: float = 0.0
        self._last_rx_at: float = 0.0
        self._last_tx_at: float = 0.0
        self._started_at: float = 0.0

    # ---- lifecycle ----
    def start(self) -> None:
        try:
            self._open_socket_and_resolve()
            self._open_adapter()
            self._configure_adapter()
            self._do_handshake()
            self._configure_routes()
            self._start_io_threads()
            self._started_at = time.time()
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        self._stop.set()
        if self._udp is not None:
            try:
                self._udp.close()
            except Exception:
                pass
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=2.0)
        self._threads = []
        for cidr in self._added_routes:
            try:
                netcfg.delete_route(self.config.name, cidr)
            except Exception:
                pass
        self._added_routes = []
        if self._endpoint_route_added:
            try:
                netcfg.delete_route_via(self._endpoint_route_added)
            except Exception:
                pass
            self._endpoint_route_added = None
        if self._adapter is not None:
            try:
                self._adapter.close()
            except Exception:
                pass
            self._adapter = None

    # ---- setup steps ----
    def _open_socket_and_resolve(self) -> None:
        host, port = self.config.peer_endpoint
        ip = socket.gethostbyname(host)
        self._endpoint = (ip, port)
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("", 0))

    def _open_adapter(self) -> None:
        self._adapter = wintun.Adapter(self.config.name, "WireGuard")
        self._session = self._adapter.start_session()

    def _configure_adapter(self) -> None:
        # Wintun is point-to-point. Always assign the interface IP as /32
        # (or /128 for v6) regardless of what the .conf prefix says — any
        # wider mask makes Windows auto-add an On-link route covering that
        # whole subnet (e.g. a /0 mask creates a 0.0.0.0/0 On-link route
        # that hijacks the WG-server UDP itself, breaking the tunnel).
        for i, cidr in enumerate(self.config.address):
            try:
                ip_obj = ipaddress.ip_interface(cidr).ip
                host_cidr = f"{ip_obj}/{'32' if ip_obj.version == 4 else '128'}"
                if i == 0:
                    netcfg.set_address(self.config.name, host_cidr)
                else:
                    netcfg.add_address(self.config.name, host_cidr)
            except Exception:
                pass
        if self.config.dns:
            try:
                netcfg.set_dns(self.config.name, self.config.dns)
            except Exception:
                pass

    def _do_handshake(self) -> None:
        priv = wgproto.x25519_priv_from_bytes(self.config.private_key)
        pub = wgproto.x25519_pub_bytes(priv)
        state = wgproto.HandshakeState(
            static_private=priv, static_public=pub,
            peer_static_public=self.config.peer_public,
            preshared_key=self.config.preshared_key,
        )
        last_err = None
        for attempt in range(self.HANDSHAKE_ATTEMPTS):
            msg = wgproto.build_initiation(state)
            self._udp.settimeout(self.HANDSHAKE_TIMEOUT)
            try:
                self._udp.sendto(msg, self._endpoint)
                while True:
                    data, src = self._udp.recvfrom(2048)
                    if not data:
                        continue
                    msg_type = data[0] if data else 0
                    if msg_type == wgproto.MSG_RESPONSE and wgproto.consume_response(state, data):
                        self._state = state
                        self._last_handshake_at = time.time()
                        self._udp.settimeout(None)
                        return
                    # Ignore cookies/transport at this stage; loop until timeout
            except socket.timeout:
                last_err = TimeoutError(f"handshake attempt {attempt + 1} timed out")
                continue
            except OSError as e:
                last_err = e
                break
        raise RuntimeError(f"handshake failed: {last_err}")

    def _configure_routes(self) -> None:
        # Pin WG server endpoint to the real default gateway so encrypted UDP
        # never goes through our own tunnel (would be a recursive loop).
        try:
            gw = netcfg.get_default_gateway(4)
            if gw:
                endpoint_cidr = f"{self._endpoint[0]}/32"
                netcfg.add_route_via(endpoint_cidr, gw, metric=1)
                self._endpoint_route_added = endpoint_cidr
        except Exception:
            pass

        # For AllowedIPs, expand "catch-all" prefixes to two /1 halves so the
        # original 0.0.0.0/0 default route remains free for endpoint traffic.
        expanded: list[str] = []
        for cidr in self.config.allowed_ips:
            if cidr.strip() in ("0.0.0.0/0", "0/0"):
                expanded += ["0.0.0.0/1", "128.0.0.0/1"]
            elif cidr.strip() == "::/0":
                expanded += ["::/1", "8000::/1"]
            else:
                expanded.append(cidr)
        for cidr in expanded:
            try:
                netcfg.add_route(self.config.name, cidr, metric=5)
                self._added_routes.append(cidr)
            except Exception:
                pass

    # ---- IO threads ----
    def _start_io_threads(self) -> None:
        self._stop.clear()
        t1 = threading.Thread(target=self._tun_to_udp_loop,
                              name=f"tun→udp[{self.config.name}]", daemon=True)
        t2 = threading.Thread(target=self._udp_to_tun_loop,
                              name=f"udp→tun[{self.config.name}]", daemon=True)
        t3 = threading.Thread(target=self._timer_loop,
                              name=f"timers[{self.config.name}]", daemon=True)
        t1.start(); t2.start(); t3.start()
        self._threads = [t1, t2, t3]

    def _tun_to_udp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                pkt = self._session.receive_packet(wait_ms=500)
            except Exception:
                break
            if pkt is None:
                continue
            try:
                enc = wgproto.build_transport(self._state, pkt)
                self._udp.sendto(enc, self._endpoint)
                with self._lock:
                    self._tx += len(pkt)
                    self._last_tx_at = time.time()
            except Exception:
                continue

    def _udp_to_tun_loop(self) -> None:
        buf_size = 65535
        while not self._stop.is_set():
            try:
                data, _ = self._udp.recvfrom(buf_size)
            except (OSError, socket.error):
                break
            if not data:
                continue
            msg_type = data[0]
            if msg_type == wgproto.MSG_TRANSPORT:
                pt = wgproto.consume_transport(self._state, self._replay, data)
                if pt is None or not pt:
                    continue
                try:
                    self._session.send_packet(pt)
                    with self._lock:
                        self._rx += len(pt)
                        self._last_rx_at = time.time()
                except Exception:
                    continue
            # else: ignore cookies/init/response — rekey not implemented here

    def _timer_loop(self) -> None:
        next_keepalive = (
            time.time() + self.config.persistent_keepalive
            if self.config.persistent_keepalive > 0 else None
        )
        while not self._stop.is_set():
            time.sleep(1.0)
            now = time.time()
            if next_keepalive is not None and now >= next_keepalive:
                try:
                    enc = wgproto.build_transport(self._state, b"")
                    self._udp.sendto(enc, self._endpoint)
                    with self._lock:
                        self._last_tx_at = now
                except Exception:
                    pass
                next_keepalive = now + self.config.persistent_keepalive

    # ---- stats ----
    @property
    def is_running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "rx_bytes": self._rx,
                "tx_bytes": self._tx,
                "last_handshake": self._last_handshake_at,
                "endpoint": f"{self._endpoint[0]}:{self._endpoint[1]}",
                "started_at": self._started_at,
                "last_rx_at": self._last_rx_at,
                "last_tx_at": self._last_tx_at,
            }
