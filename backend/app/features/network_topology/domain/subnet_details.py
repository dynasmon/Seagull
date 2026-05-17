from __future__ import annotations

from datetime import datetime
from typing import Any

from app.features.network_topology.domain.serializers import _to_utc


def _severity_weight(value: Any) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
    }.get(str(value or "").lower(), 0)

def _topology_node_sort_key(node: Any) -> tuple[int, int, int, int, float]:
    last_seen = _to_utc(getattr(node, "last_seen_at", None)).timestamp()
    return (
        -_severity_weight(getattr(node, "severity", None)),
        -int(getattr(node, "risk_score", 0) or 0),
        -int(getattr(node, "alert_count", 0) or 0),
        -int(getattr(node, "event_count", 0) or 0),
        -last_seen,
    )

def _topology_edge_sort_key(edge: Any) -> tuple[int, int, int, float]:
    last_seen = _to_utc(getattr(edge, "last_seen_at", None)).timestamp()
    return (
        -_severity_weight(getattr(edge, "severity", None)),
        -int(getattr(edge, "alert_count", 0) or 0),
        -int(getattr(edge, "event_count", 0) or 0),
        -last_seen,
    )

def _highest_node_severity(nodes: list[Any]) -> str:
    if not nodes:
        return "unknown"
    return str(max(nodes, key=lambda node: _severity_weight(getattr(node, "severity", None))).severity or "unknown")

def _edge_has_gateway_metadata(edge: Any) -> bool:
    metadata = edge.extra_data if isinstance(getattr(edge, "extra_data", None), dict) else {}
    for key, value in metadata.items():
        normalized_key = str(key or "").strip().lower().replace("-", "_")
        normalized_value = str(value or "").strip().lower().replace("-", "_")
        if "gateway" in normalized_key and bool(value):
            return True
        if normalized_key in {"role", "type", "kind"} and normalized_value in {"gateway", "default_gateway", "next_hop"}:
            return True
    return False

def _dedupe_sorted_nodes(nodes: list[Any]) -> list[Any]:
    ordered = sorted(nodes, key=_topology_node_sort_key)
    out: list[Any] = []
    seen: set[str] = set()
    for node in ordered:
        key = str(getattr(node, "node_key", "") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(node)
    return out

def _subnet_gateway_candidates(
    *,
    member_nodes: list[Any],
    related_edges: list[Any],
    node_by_key: dict[str, Any],
    member_keys: set[str],
) -> list[Any]:
    candidates: list[Any] = [
        node
        for node in member_nodes
        if str(getattr(node, "node_type", "") or "").lower() == "gateway"
    ]
    for edge in related_edges:
        edge_type = str(getattr(edge, "edge_type", "") or "").lower()
        if edge_type == "route_next_hop":
            for key in (edge.source_node_key, edge.target_node_key):
                node = node_by_key.get(key)
                if node and str(getattr(node, "node_type", "") or "").lower() == "gateway":
                    candidates.append(node)
        if edge_type == "member_of_subnet" and _edge_has_gateway_metadata(edge):
            source = node_by_key.get(edge.source_node_key)
            if source and edge.source_node_key in member_keys:
                candidates.append(source)
    return _dedupe_sorted_nodes(candidates)

def _node_ip_scope(node: Any) -> str:
    metadata = node.extra_data if isinstance(getattr(node, "extra_data", None), dict) else {}
    return str(metadata.get("ip_scope") or "").strip().lower()

def _subnet_exposed_or_public_nodes(member_nodes: list[Any]) -> list[Any]:
    out: list[Any] = []
    for node in member_nodes:
        metadata = node.extra_data if isinstance(getattr(node, "extra_data", None), dict) else {}
        if _node_ip_scope(node) == "public_internet" or bool(metadata.get("has_exposure_findings")) or bool(metadata.get("exposure_asset_key")):
            out.append(node)
    return _dedupe_sorted_nodes(out)

def _subnet_listening_services(
    *,
    member_nodes: list[Any],
    related_edges: list[Any],
    node_by_key: dict[str, Any],
    member_keys: set[str],
) -> list[Any]:
    services: list[Any] = [
        node
        for node in member_nodes
        if str(getattr(node, "node_type", "") or "").lower() == "service"
    ]
    for edge in related_edges:
        if str(getattr(edge, "edge_type", "") or "").lower() != "listens_on":
            continue
        if edge.source_node_key in member_keys:
            target = node_by_key.get(edge.target_node_key)
            if target and str(getattr(target, "node_type", "") or "").lower() == "service":
                services.append(target)
        if edge.target_node_key in member_keys:
            source = node_by_key.get(edge.source_node_key)
            if source and str(getattr(source, "node_type", "") or "").lower() == "service":
                services.append(source)
    return _dedupe_sorted_nodes(services)

def _subnet_external_destinations(
    *,
    related_edges: list[Any],
    node_by_key: dict[str, Any],
    member_keys: set[str],
) -> list[Any]:
    destinations: list[Any] = []
    for edge in related_edges:
        if edge.source_node_key in member_keys:
            candidate = node_by_key.get(edge.target_node_key)
        elif edge.target_node_key in member_keys:
            candidate = node_by_key.get(edge.source_node_key)
        else:
            continue
        if candidate is None:
            continue
        if str(getattr(candidate, "node_type", "") or "").lower() == "external_ip" or _node_ip_scope(candidate) == "public_internet":
            destinations.append(candidate)
    return _dedupe_sorted_nodes(destinations)

def _earliest_dt(*values: datetime | None) -> datetime | None:
    present = [value for value in values if value is not None]
    return min(present) if present else None

def _latest_dt(*values: datetime | None) -> datetime | None:
    present = [value for value in values if value is not None]
    return max(present) if present else None
