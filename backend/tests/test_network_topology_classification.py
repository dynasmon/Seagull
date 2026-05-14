from __future__ import annotations

import pytest

from app.features.network_topology.classification import (
    EDGE_TYPES,
    NODE_TYPES,
    classify_topology_flow,
    classify_topology_ip,
    infer_subnet_cidr,
)
from app.shared.network.ip_classification import classify_flow, classify_ip

# ---- Reuse assertion: classify_topology_ip delegates to classify_ip ----------------

def test_classify_topology_ip_delegates_scope_to_classify_ip() -> None:
    base = classify_ip("8.8.8.8")
    topo = classify_topology_ip("8.8.8.8")
    assert topo["scope"] == base["scope"]
    assert topo["is_public"] == base["is_public"]
    assert topo["is_internal"] == base["is_internal"]
    assert topo["version"] == base["version"]


def test_classify_topology_flow_delegates_locality_to_classify_flow() -> None:
    base = classify_flow("192.168.1.1", "8.8.8.8")
    topo = classify_topology_flow("192.168.1.1", "8.8.8.8")
    assert topo["flow"]["locality"] == base["flow"]["locality"]
    assert topo["src"]["scope"] == base["src"]["scope"]
    assert topo["dst"]["scope"] == base["dst"]["scope"]


# ---- node_class derivation --------------------------------------------------------

def test_public_ip_maps_to_external_ip() -> None:
    r = classify_topology_ip("8.8.8.8")
    assert r["node_class"] == "external_ip"


def test_private_rfc1918_maps_to_host() -> None:
    r = classify_topology_ip("10.0.0.5")
    assert r["node_class"] == "host"


def test_loopback_maps_to_interface() -> None:
    r = classify_topology_ip("127.0.0.1")
    assert r["node_class"] == "interface"


def test_link_local_maps_to_interface() -> None:
    r = classify_topology_ip("169.254.1.1")
    assert r["node_class"] == "interface"


def test_cgnat_maps_to_gateway() -> None:
    r = classify_topology_ip("100.64.0.1")
    assert r["node_class"] == "gateway"


def test_ipv6_unique_local_maps_to_host() -> None:
    r = classify_topology_ip("fd00::1")
    assert r["node_class"] == "host"


def test_invalid_ip_maps_to_unknown() -> None:
    r = classify_topology_ip("not-an-ip")
    assert r["node_class"] == "unknown"


def test_none_ip_maps_to_unknown() -> None:
    r = classify_topology_ip(None)
    assert r["node_class"] == "unknown"


def test_docker_bridge_ip_maps_to_docker_network() -> None:
    r = classify_topology_ip("172.17.0.5")
    assert r["node_class"] == "docker_network"


def test_docker_bridge_ip_outside_default_maps_to_host() -> None:
    # 172.18.0.0/16 is also Docker range but outside 172.17.0.0/16
    r = classify_topology_ip("172.18.0.5")
    assert r["node_class"] == "host"


def test_configured_cidr_override_still_maps_to_host() -> None:
    r = classify_topology_ip("203.0.113.5", internal_cidrs=["203.0.113.0/24"])
    assert r["scope"] == "internal_network"
    assert r["node_class"] == "host"


# ---- node_class added to flow endpoints -------------------------------------------

def test_flow_adds_node_class_to_src_and_dst() -> None:
    r = classify_topology_flow("192.168.1.1", "8.8.8.8")
    assert "node_class" in r["src"]
    assert "node_class" in r["dst"]
    assert r["src"]["node_class"] == "host"
    assert r["dst"]["node_class"] == "external_ip"


def test_flow_with_configured_cidrs_respected() -> None:
    r = classify_topology_flow("10.20.30.1", "1.1.1.1", internal_cidrs=["10.20.30.0/24"])
    assert r["src"]["scope"] == "internal_network"
    assert r["src"]["node_class"] == "host"
    assert r["dst"]["node_class"] == "external_ip"
    assert r["flow"]["locality"] == "internal_to_public"


# ---- infer_subnet_cidr ------------------------------------------------------------

def test_infer_subnet_cidr_basic() -> None:
    cidr = infer_subnet_cidr("10.0.0.5")
    assert cidr == "10.0.0.0/24"


def test_infer_subnet_cidr_preserves_network_bits() -> None:
    cidr = infer_subnet_cidr("192.168.1.200")
    assert cidr == "192.168.1.0/24"


def test_infer_subnet_cidr_custom_prefix() -> None:
    cidr = infer_subnet_cidr("10.1.2.3", prefix_len=16)
    assert cidr == "10.1.0.0/16"


def test_infer_subnet_cidr_invalid_returns_none() -> None:
    result = infer_subnet_cidr("not-an-ip")
    assert result is None


def test_infer_subnet_cidr_ipv6() -> None:
    cidr = infer_subnet_cidr("fd00::1", prefix_len=64)
    assert cidr is not None
    assert "/" in cidr


# ---- constant sets ----------------------------------------------------------------

def test_node_types_contains_required_types() -> None:
    required = {"agent", "host", "interface", "subnet", "service", "external_ip", "gateway", "docker_network", "unknown"}
    assert required.issubset(NODE_TYPES)


def test_edge_types_contains_required_types() -> None:
    required = {
        "owns_interface", "member_of_subnet", "observed_flow", "listens_on",
        "resolved_dns", "alert_related", "exposure_related", "route_next_hop",
        "same_agent", "inferred_relationship",
    }
    assert required.issubset(EDGE_TYPES)


# ---- no duplication: verify classify_ip / classify_flow are reused -----------------

def test_topology_ip_result_contains_all_base_keys() -> None:
    base_keys = {"ip", "version", "scope", "label", "is_internal", "is_public", "is_special", "matched_cidr", "match_source"}
    r = classify_topology_ip("10.0.0.1")
    assert base_keys.issubset(set(r.keys()))


def test_topology_flow_result_contains_all_base_flow_keys() -> None:
    r = classify_topology_flow("10.0.0.1", "8.8.8.8")
    assert "flow" in r
    assert "locality" in r["flow"]
    assert "src_internal" in r["flow"]
    assert "dst_internal" in r["flow"]


# ---- IP scope classifications consistent with ip_classification module --------------

@pytest.mark.parametrize("ip,expected_scope", [
    ("10.0.0.1", "private_address"),
    ("172.16.0.1", "private_address"),
    ("192.168.1.1", "private_address"),
    ("127.0.0.1", "loopback"),
    ("169.254.0.1", "link_local"),
    ("100.64.0.1", "cgnat"),
    ("8.8.8.8", "public_internet"),
    ("224.0.0.1", "multicast"),
    ("::1", "loopback"),
    ("fd00::1", "unique_local"),
    ("fe80::1", "link_local"),
])
def test_topology_ip_scope_matches_classify_ip(ip: str, expected_scope: str) -> None:
    topo = classify_topology_ip(ip)
    base = classify_ip(ip)
    assert topo["scope"] == base["scope"] == expected_scope
