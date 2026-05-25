"""Network configuration for Wintun adapters: IP, DNS, routes.

Uses `netsh` subprocess for portability across Windows 10/11. Admin required.
"""
import ipaddress
import subprocess
from typing import Optional

import applog

log = applog.get("netcfg")

_NO_WIN = 0
try:
    _NO_WIN = subprocess.CREATE_NO_WINDOW
except AttributeError:
    pass


def _netsh(*args: str) -> tuple[int, str]:
    r = subprocess.run(["netsh", *args], capture_output=True, text=True,
                       creationflags=_NO_WIN)
    out = (r.stdout + r.stderr).strip()
    log.debug("netsh %s -> rc=%d %s", " ".join(args), r.returncode, out[:200])
    return r.returncode, out


def _ipv4_mask(prefix_len: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)


def set_address(adapter_name: str, cidr: str) -> None:
    """Assign a primary IP to the adapter, replacing any existing."""
    iface = ipaddress.ip_interface(cidr)
    if iface.version == 4:
        rc, out = _netsh(
            "interface", "ipv4", "set", "address",
            f"name={adapter_name}", "source=static",
            f"address={iface.ip}", f"mask={_ipv4_mask(iface.network.prefixlen)}",
        )
    else:
        rc, out = _netsh(
            "interface", "ipv6", "add", "address",
            f"interface={adapter_name}",
            f"address={iface.ip}/{iface.network.prefixlen}",
        )
    if rc != 0:
        raise RuntimeError(f"set_address({cidr}): {out}")


def add_address(adapter_name: str, cidr: str) -> None:
    """Add an additional IP to the adapter."""
    iface = ipaddress.ip_interface(cidr)
    if iface.version == 4:
        rc, out = _netsh(
            "interface", "ipv4", "add", "address",
            f"name={adapter_name}",
            f"address={iface.ip}",
            f"mask={_ipv4_mask(iface.network.prefixlen)}",
        )
    else:
        rc, out = _netsh(
            "interface", "ipv6", "add", "address",
            f"interface={adapter_name}",
            f"address={iface.ip}/{iface.network.prefixlen}",
        )
    if rc != 0:
        raise RuntimeError(f"add_address({cidr}): {out}")


def set_dns(adapter_name: str, servers: list[str]) -> None:
    """Set DNS servers (clears existing). Empty list reverts to DHCP."""
    if not servers:
        _netsh("interface", "ipv4", "set", "dnsservers",
               f"name={adapter_name}", "source=dhcp")
        _netsh("interface", "ipv6", "set", "dnsservers",
               f"name={adapter_name}", "source=dhcp")
        return
    v4 = [s for s in servers if ":" not in s]
    v6 = [s for s in servers if ":" in s]
    if v4:
        _netsh("interface", "ipv4", "set", "dnsservers",
               f"name={adapter_name}", "static", v4[0], "validate=no")
        for i, s in enumerate(v4[1:], start=2):
            _netsh("interface", "ipv4", "add", "dnsservers",
                   f"name={adapter_name}", s, f"index={i}", "validate=no")
    if v6:
        _netsh("interface", "ipv6", "set", "dnsservers",
               f"name={adapter_name}", "static", v6[0], "validate=no")
        for i, s in enumerate(v6[1:], start=2):
            _netsh("interface", "ipv6", "add", "dnsservers",
                   f"name={adapter_name}", s, f"index={i}", "validate=no")


def add_route(adapter_name: str, dest_cidr: str, metric: int = 1) -> None:
    net = ipaddress.ip_network(dest_cidr, strict=False)
    family = "ipv4" if net.version == 4 else "ipv6"
    rc, out = _netsh(
        "interface", family, "add", "route",
        f"prefix={net.with_prefixlen}",
        f"interface={adapter_name}",
        f"metric={metric}", "store=active",
    )
    if rc != 0:
        raise RuntimeError(f"add_route({dest_cidr}): {out}")


def delete_route(adapter_name: str, dest_cidr: str) -> None:
    net = ipaddress.ip_network(dest_cidr, strict=False)
    family = "ipv4" if net.version == 4 else "ipv6"
    _netsh(
        "interface", family, "delete", "route",
        f"prefix={net.with_prefixlen}",
        f"interface={adapter_name}",
    )


def add_route_via(dest_cidr: str, gateway: str, interface: str,
                  metric: int = 1) -> None:
    """Add a route via a specific next-hop gateway on a given interface.

    Used to force WG-server endpoint traffic to go through the user's real
    default gateway when AllowedIPs include 0.0.0.0/0.

    netsh `add route` REQUIRES `interface=`; without it netsh prints
    "One or more essential parameters were not entered" yet still exits 0,
    so we must validate the textual output, not just the return code.
    """
    net = ipaddress.ip_network(dest_cidr, strict=False)
    family = "ipv4" if net.version == 4 else "ipv6"
    rc, out = _netsh(
        "interface", family, "add", "route",
        f"prefix={net.with_prefixlen}",
        f"interface={interface}",
        f"nexthop={gateway}",
        f"metric={metric}", "store=active",
    )
    if rc != 0 or "ok." not in out.lower():
        raise RuntimeError(
            f"add_route_via({dest_cidr} via {gateway} if {interface}): {out}")


def delete_route_via(dest_cidr: str, interface: str) -> None:
    net = ipaddress.ip_network(dest_cidr, strict=False)
    family = "ipv4" if net.version == 4 else "ipv6"
    _netsh(
        "interface", family, "delete", "route",
        f"prefix={net.with_prefixlen}",
        f"interface={interface}",
    )


def get_default_gateway_info(family: int = 4) -> Optional[tuple[str, Optional[int]]]:
    """Return (gateway_ip, interface_index) for the lowest-metric default route.

    The interface index is needed because netsh `add route` requires an
    explicit `interface=` even when a next-hop gateway is given.
    """
    fam = "ipv4" if family == 4 else "ipv6"
    target = "0.0.0.0/0" if family == 4 else "::/0"
    r = subprocess.run(
        ["netsh", "interface", fam, "show", "route"],
        capture_output=True, text=True, creationflags=_NO_WIN,
    )
    best = None
    best_idx = None
    best_metric = None
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or target not in line:
            continue
        parts = line.split()
        # Format columns: Publish Type Met Prefix Idx Gateway/Interface Name
        try:
            met_pos = next(i for i, p in enumerate(parts) if p.isdigit())
            metric = int(parts[met_pos])
        except StopIteration:
            continue
        # The next IP-looking token is the gateway; the digit token right
        # before it is the interface index.
        for j in range(met_pos + 1, len(parts)):
            try:
                ipaddress.ip_address(parts[j])
            except ValueError:
                continue
            idx = int(parts[j - 1]) if parts[j - 1].isdigit() else None
            if best_metric is None or metric < best_metric:
                best, best_idx, best_metric = parts[j], idx, metric
            break
    if best is None:
        return None
    return best, best_idx


def get_default_gateway(family: int = 4) -> Optional[str]:
    """Return current default gateway IP (the user's real internet gateway)."""
    info = get_default_gateway_info(family)
    return info[0] if info else None


def get_adapter_index(adapter_name: str) -> Optional[int]:
    r = subprocess.run(
        ["netsh", "interface", "ipv4", "show", "interfaces"],
        capture_output=True, text=True, creationflags=_NO_WIN,
    )
    for line in r.stdout.splitlines():
        if adapter_name in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                return int(parts[0])
    return None


def flush_dns_cache() -> None:
    subprocess.run(["ipconfig", "/flushdns"],
                   capture_output=True, creationflags=_NO_WIN)
