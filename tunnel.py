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

import applog
import netcfg
import wgproto
import wintun

log = applog.get("tunnel")


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
    # per-tunnel split routing (set by wgapi from app settings, not from .conf)
    split_mode: str = "off"                 # "off" | "exclude" | "include"
    split_rules: list[str] = field(default_factory=list)  # IPs/CIDRs/domains


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
        # rekey machinery: previous keypair kept briefly to decrypt in-flight
        # packets, plus the pending handshake we are negotiating.
        self._prev_state: Optional[wgproto.HandshakeState] = None
        self._prev_replay: Optional[wgproto.ReplayWindow] = None
        self._prev_until: float = 0.0
        self._pending: Optional[wgproto.HandshakeState] = None
        self._pending_msg: Optional[bytes] = None
        self._pending_since: float = 0.0
        self._pending_last_send: float = 0.0
        self._send_lock = threading.Lock()  # serialize send_counter increments
        self._endpoint: tuple[str, int] = ("", 0)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._added_routes: list[str] = []
        self._endpoint_route_added: Optional[tuple[str, str]] = None
        self._bypass_routes: list[tuple[str, str]] = []  # split-exclude routes

        self._lock = threading.Lock()
        self._rx = 0
        self._tx = 0
        self._last_handshake_at: float = 0.0
        self._last_rx_at: float = 0.0
        self._last_tx_at: float = 0.0
        self._started_at: float = 0.0

    # ---- lifecycle ----
    def start(self) -> None:
        log.info("start[%s] begin: peer=%s allowed_ips=%s addr=%s dns=%s",
                 self.config.name, self.config.peer_endpoint,
                 self.config.allowed_ips, self.config.address, self.config.dns)
        try:
            self._open_socket_and_resolve()
            log.info("start[%s] step1 OK: endpoint resolved -> %s",
                     self.config.name, self._endpoint)
            self._open_adapter()
            log.info("start[%s] step2 OK: adapter opened, session started",
                     self.config.name)
            self._configure_adapter()
            log.info("start[%s] step3 OK: adapter IP/DNS configured",
                     self.config.name)
            self._do_handshake()
            log.info("start[%s] step4 OK: handshake complete, remote_idx=%#x",
                     self.config.name, self._state.remote_index)
            self._configure_routes()
            log.info("start[%s] step5 OK: routes added=%s endpoint_route=%s",
                     self.config.name, self._added_routes, self._endpoint_route_added)
            self._start_io_threads()
            log.info("start[%s] step6 OK: IO threads running", self.config.name)
            self._started_at = time.time()
        except Exception as e:
            log.exception("start[%s] FAILED: %s", self.config.name, e)
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
            cidr, iface = self._endpoint_route_added
            try:
                netcfg.delete_route_via(cidr, iface)
            except Exception:
                pass
            self._endpoint_route_added = None
        for cidr, iface in self._bypass_routes:
            try:
                netcfg.delete_route_via(cidr, iface)
            except Exception:
                pass
        self._bypass_routes = []
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
        # Big send/recv buffers so bursts don't drop at the socket layer under
        # load (dropped UDP = retransmits upstream = visible speed dips).
        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                self._udp.setsockopt(socket.SOL_SOCKET, opt, 4 * 1024 * 1024)
            except OSError:
                pass
        self._udp.bind(("", 0))

    def _open_adapter(self) -> None:
        self._adapter = wintun.Adapter(self.config.name, "WireGuard")
        # 8 MiB ring (default 4) — more headroom for high-throughput bursts.
        self._session = self._adapter.start_session(0x800000)

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

    def _make_state(self) -> wgproto.HandshakeState:
        priv = wgproto.x25519_priv_from_bytes(self.config.private_key)
        pub = wgproto.x25519_pub_bytes(priv)
        return wgproto.HandshakeState(
            static_private=priv, static_public=pub,
            peer_static_public=self.config.peer_public,
            preshared_key=self.config.preshared_key,
        )

    def _do_handshake(self) -> None:
        state = self._make_state()
        last_err = None
        for attempt in range(self.HANDSHAKE_ATTEMPTS):
            msg = wgproto.build_initiation(state)
            self._udp.settimeout(self.HANDSHAKE_TIMEOUT)
            log.info("handshake attempt %d/%d: sending %d-byte initiation to %s (local_idx=%#x)",
                     attempt + 1, self.HANDSHAKE_ATTEMPTS, len(msg),
                     self._endpoint, state.local_index)
            try:
                self._udp.sendto(msg, self._endpoint)
                while True:
                    data, src = self._udp.recvfrom(2048)
                    log.info("handshake recv: %d bytes from %s, type=%d",
                             len(data) if data else 0, src,
                             data[0] if data else -1)
                    if not data:
                        continue
                    msg_type = data[0] if data else 0
                    if msg_type == wgproto.MSG_RESPONSE:
                        ok = wgproto.consume_response(state, data)
                        log.info("handshake: consume_response -> %s", ok)
                        if ok:
                            self._state = state
                            self._last_handshake_at = time.time()
                            self._udp.settimeout(None)
                            return
                    # Ignore cookies/transport at this stage; loop until timeout
            except socket.timeout:
                last_err = TimeoutError(f"handshake attempt {attempt + 1} timed out")
                log.warning("handshake: attempt %d timed out", attempt + 1)
                continue
            except OSError as e:
                last_err = e
                log.warning("handshake: socket error: %s", e)
                break
        log.error("handshake FAILED after %d attempts: %s",
                  self.HANDSHAKE_ATTEMPTS, last_err)
        raise RuntimeError(f"handshake failed: {last_err}")

    def _resolve_rules(self, rules: list[str]) -> list[str]:
        """Turn split rules (IP / CIDR / domain) into concrete host CIDRs.
        Domains are resolved now (before tunnel routes exist) via normal DNS;
        CDNs with rotating IPs are only covered for the IPs seen at connect."""
        out: list[str] = []
        seen: set[str] = set()
        for raw in rules:
            r = raw.strip()
            if not r:
                continue
            try:
                net = ipaddress.ip_network(r, strict=False)
                if net.with_prefixlen not in seen:
                    seen.add(net.with_prefixlen)
                    out.append(net.with_prefixlen)
                continue
            except ValueError:
                pass
            try:
                for info in socket.getaddrinfo(r, None):
                    ip = info[4][0]
                    v = ipaddress.ip_address(ip)
                    cidr = f"{ip}/{'32' if v.version == 4 else '128'}"
                    if cidr not in seen:
                        seen.add(cidr)
                        out.append(cidr)
            except Exception as e:
                log.warning("split: cannot resolve rule %r: %s", r, e)
        return out

    def _configure_routes(self) -> None:
        mode = self.config.split_mode
        rules = (self._resolve_rules(self.config.split_rules)
                 if mode in ("exclude", "include") else [])
        full_tunnel = any(
            c.strip() in ("0.0.0.0/0", "0/0", "::/0")
            for c in self.config.allowed_ips
        )
        gw_info = netcfg.get_default_gateway_info(4)
        gw = ifidx = None
        if gw_info and gw_info[1] is not None:
            gw, ifidx = gw_info[0], str(gw_info[1])

        # We only capture the default route (and thus need the endpoint pin) in
        # off/exclude modes on a full tunnel. In include mode only the listed
        # prefixes are routed, so the server endpoint is reached normally.
        capture_default = full_tunnel and mode != "include"

        # Pin WG server endpoint to the real default gateway so encrypted UDP
        # never loops back through our own tunnel.
        endpoint_cidr = f"{self._endpoint[0]}/32"
        if gw and ifidx and capture_default:
            netcfg.add_route_via(endpoint_cidr, gw, ifidx, metric=1)
            self._endpoint_route_added = (endpoint_cidr, ifidx)
            log.info("endpoint pinned: %s via %s on if %s", endpoint_cidr, gw, ifidx)
        elif capture_default:
            raise RuntimeError(
                f"cannot pin endpoint {endpoint_cidr}: no default gateway "
                f"with interface index found (got {gw_info!r})")

        if mode == "include":
            # whitelist: ONLY these destinations go through the tunnel
            targets = rules or list(self.config.allowed_ips)
            for cidr in targets:
                try:
                    netcfg.add_route(self.config.name, cidr, metric=5)
                    self._added_routes.append(cidr)
                except Exception:
                    pass
            log.info("split include: %d prefix(es) routed through tunnel",
                     len(self._added_routes))
            return

        # off / exclude: install AllowedIPs, expanding the 0.0.0.0/0 catch-all
        # into two /1 halves so the real default route stays free for the pin.
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

        if mode == "exclude" and rules:
            if not (gw and ifidx):
                log.warning("split exclude: no gateway, cannot add bypass routes")
            else:
                for cidr in rules:
                    try:
                        netcfg.add_route_via(cidr, gw, ifidx, metric=1)
                        self._bypass_routes.append((cidr, ifidx))
                    except Exception as e:
                        log.warning("split exclude: bypass %s failed: %s", cidr, e)
                log.info("split exclude: %d prefix(es) bypass the tunnel",
                         len(self._bypass_routes))

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
        sent = 0
        while not self._stop.is_set():
            try:
                pkt = self._session.receive_packet(wait_ms=500)
            except Exception as e:
                log.warning("tun→udp: session.receive_packet error: %s", e)
                break
            if pkt is None:
                continue
            try:
                enc_len = self._encrypt_send(pkt)
                with self._lock:
                    self._tx += len(pkt)
                    self._last_tx_at = time.time()
                sent += 1
                if sent <= 5 or sent % 200 == 0:
                    log.debug("tun→udp #%d: %d B plaintext → %d B ciphertext to %s",
                              sent, len(pkt), enc_len, self._endpoint)
            except Exception as e:
                log.warning("tun→udp: send error: %s", e)
                continue

    def _udp_to_tun_loop(self) -> None:
        buf_size = 65535
        recv_total = 0
        recv_transport = 0
        recv_other = 0
        decrypt_fail = 0
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(buf_size)
            except (OSError, socket.error) as e:
                log.info("udp→tun: socket closed/error: %s", e)
                break
            if not data:
                continue
            recv_total += 1
            msg_type = data[0]
            if msg_type == wgproto.MSG_TRANSPORT:
                pt = wgproto.consume_transport(self._state, self._replay, data)
                # During a rekey the server may still send a few packets under
                # the previous keypair — accept them for a short grace period.
                if (pt is None and self._prev_state is not None
                        and time.time() < self._prev_until):
                    pt = wgproto.consume_transport(
                        self._prev_state, self._prev_replay, data)
                if pt is None:
                    decrypt_fail += 1
                    if decrypt_fail <= 5 or decrypt_fail % 100 == 0:
                        log.warning("udp→tun: decrypt FAILED (#%d) from %s, %d B",
                                    decrypt_fail, addr, len(data))
                    continue
                if not pt:
                    # Keepalive (empty payload) — valid but nothing to write
                    log.debug("udp→tun: keepalive received from %s", addr)
                    continue
                try:
                    self._session.send_packet(pt)
                    with self._lock:
                        self._rx += len(pt)
                        self._last_rx_at = time.time()
                    recv_transport += 1
                    if recv_transport <= 5 or recv_transport % 200 == 0:
                        log.debug("udp→tun #%d: %d B ciphertext from %s → %d B to TUN",
                                  recv_transport, len(data), addr, len(pt))
                except Exception as e:
                    log.warning("udp→tun: session.send_packet error: %s", e)
                    continue
            elif msg_type == wgproto.MSG_RESPONSE:
                self._complete_rekey(data)
            else:
                recv_other += 1
                if recv_other <= 3:
                    log.info("udp→tun: non-transport packet type=%d from %s, %d B",
                             msg_type, addr, len(data))

    def _encrypt_send(self, plaintext: bytes) -> int:
        """Encrypt under the current session and send. The send-counter bump
        inside build_transport is not atomic, so serialize it — two threads
        (data + keepalive) reusing a nonce would get rejected as a replay."""
        st = self._state
        if st is None:
            return 0
        with self._send_lock:
            enc = wgproto.build_transport(st, plaintext)
        self._udp.sendto(enc, self._endpoint)
        return len(enc)

    def _send_keepalive(self) -> None:
        try:
            self._encrypt_send(b"")
            with self._lock:
                self._last_tx_at = time.time()
        except Exception:
            pass

    def _timer_loop(self) -> None:
        # Always keep the NAT mapping warm, even if the .conf omitted it.
        ka = self.config.persistent_keepalive or 25
        next_keepalive = time.time() + ka
        while not self._stop.is_set():
            time.sleep(1.0)
            now = time.time()
            if now >= next_keepalive:
                self._send_keepalive()
                next_keepalive = now + ka
            try:
                self._rekey_tick(now)
            except Exception as e:
                log.warning("rekey: tick error: %s", e)

    # ---- rekey (initiator) ----
    def _rekey_tick(self, now: float) -> None:
        st = self._state
        if st is None or not st.established_at:
            return
        if self._pending is None:
            # WireGuard rekeys after REKEY_AFTER_TIME; without this the session
            # expires at REJECT_AFTER_TIME and the link silently dies.
            if now - st.established_at >= wgproto.REKEY_AFTER_TIME:
                self._start_rekey(now)
            return
        # A rekey is in flight: retransmit the SAME initiation periodically.
        if now - self._pending_last_send >= wgproto.REKEY_TIMEOUT:
            try:
                self._udp.sendto(self._pending_msg, self._endpoint)
                self._pending_last_send = now
            except Exception as e:
                log.warning("rekey: resend failed: %s", e)
        if now - self._pending_since >= wgproto.REKEY_ATTEMPT_TIME:
            log.warning("rekey: no response in %ds; will retry",
                        wgproto.REKEY_ATTEMPT_TIME)
            self._pending = None
            self._pending_msg = None

    def _start_rekey(self, now: float) -> None:
        new_state = self._make_state()
        try:
            msg = wgproto.build_initiation(new_state)
            self._udp.sendto(msg, self._endpoint)
        except Exception as e:
            log.warning("rekey: initiation send failed: %s", e)
            return
        self._pending = new_state
        self._pending_msg = msg
        self._pending_since = now
        self._pending_last_send = now
        log.info("rekey: started (age=%.0fs, new local_idx=%#x)",
                 now - self._state.established_at, new_state.local_index)

    def _complete_rekey(self, data: bytes) -> None:
        pend = self._pending
        if pend is None:
            return
        if not wgproto.consume_response(pend, data):
            log.info("rekey: response did not match pending handshake")
            return
        now = time.time()
        with self._lock:
            # keep the old keypair alive briefly for in-flight packets
            self._prev_state = self._state
            self._prev_replay = self._replay
            self._prev_until = now + 10.0
            self._state = pend
            self._replay = wgproto.ReplayWindow()
            self._pending = None
            self._pending_msg = None
            self._last_handshake_at = now
        log.info("rekey: COMPLETE (remote_idx=%#x)", pend.remote_index)
        # send data on the new keys immediately so the server promotes the
        # new keypair and starts replying under it.
        self._send_keepalive()

    # ---- stats ----
    @property
    def is_running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    def set_dns(self, servers: list[str]) -> None:
        """Re-apply DNS servers on the live adapter. Empty list = revert to
        the .conf's original DNS (or DHCP if the .conf had none)."""
        target = servers if servers else self.config.dns
        netcfg.set_dns(self.config.name, target)
        netcfg.flush_dns_cache()
        log.info("dns set on %s -> %s", self.config.name, target or "(dhcp)")

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
