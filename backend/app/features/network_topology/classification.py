from __future__ import annotations

import ipaddress
from typing import Any

from app.shared.network.ip_classification import classify_ip

_DOCKER_BRIDGE_DEFAULT = ipaddress.IPv4Network("172.17.0.0/16")

NODE_TYPES = frozenset({
    "agent",
    "host",
    "interface",
    "subnet",
    "service",
    "external_ip",
    "gateway",
    "docker_network",
    "unknown",
})

EDGE_TYPES = frozenset({
    "owns_interface",
    "member_of_subnet",
    "observed_flow",
    "listens_on",
    "resolved_dns",
    "alert_related",
    "exposure_related",
    "route_next_hop",
    "same_agent",
    "inferred_relationship",
})


def classify_topology_ip(
    ip: str | None,
    *,
    internal_cidrs: list[str] | None = None,
) -> dict[str, Any]:
    base = classify_ip(ip, internal_cidrs=internal_cidrs)
    node_class = _derive_node_class(base, ip)
    return {**base, "node_class": node_class}


def infer_subnet_cidr(ip: str, *, prefix_len: int = 24) -> str | None:
    try:
        net = ipaddress.ip_interface(f"{ip}/{prefix_len}").network
        return str(net)
    except Exception:
        return None


def _derive_node_class(ip_result: dict[str, Any], raw_ip: str | None) -> str:
    scope = ip_result.get("scope", "unknown")
    if scope in ("invalid", "unknown"):
        return "unknown"
    if scope == "loopback":
        return "interface"
    if scope == "public_internet":
        return "external_ip"
    if scope in ("private_address", "internal_network"):
        if raw_ip and _is_docker_bridge_ip(raw_ip):
            return "docker_network"
        return "host"
    if scope == "link_local":
        return "interface"
    if scope == "unique_local":
        return "host"
    if scope == "cgnat":
        return "gateway"
    return "unknown"


def _is_docker_bridge_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return addr in _DOCKER_BRIDGE_DEFAULT
    except Exception:
        return False
