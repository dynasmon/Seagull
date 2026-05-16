from __future__ import annotations

from typing import Any

_CHILD_KEY_HARD_CAP = 200

_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0,
}

_SCOPE_LABELS: dict[str, str] = {
    "public_internet": "Public Internet",
    "internal_network": "Internal Network",
    "private_address": "Private Network",
    "loopback": "Loopback",
    "link_local": "Link-local",
    "unique_local": "Unique Local",
    "cgnat": "CGNAT",
    "reserved": "Reserved",
    "unknown": "Unknown Scope",
}

VALID_STRATEGIES = frozenset({"auto", "agent", "subnet", "ip_scope"})


def _sev_weight(sev: str | None) -> int:
    return _SEVERITY_ORDER.get(str(sev or "").lower(), 0)


def _highest_sev(sevs: list[str]) -> str:
    if not sevs:
        return "unknown"
    return max(sevs, key=_sev_weight)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _ip_scope(node: Any) -> str:
    extra = node.extra_data if isinstance(node.extra_data, dict) else {}
    return _clean(extra.get("ip_scope", "")).lower()


def _has_exposure(node: Any) -> bool:
    extra = node.extra_data if isinstance(node.extra_data, dict) else {}
    return bool(_clean(extra.get("exposure_asset_key", "")))


def _node_group_key(node: Any, subnet_by_node_key: dict[str, str], strategy: str) -> str:
    if strategy == "agent":
        agent = _clean(node.agent_id)
        return f"agent:{agent}" if agent else "ungrouped"

    if strategy == "subnet":
        subnet = subnet_by_node_key.get(node.node_key)
        if subnet:
            return f"subnet:{subnet}"
        cidr = _clean(node.cidr)
        if cidr:
            return f"subnet:{cidr}"
        return "ungrouped"

    if strategy == "ip_scope":
        scope = _ip_scope(node)
        return f"scope:{scope}" if scope else "ungrouped"

    agent = _clean(node.agent_id)
    if agent:
        return f"agent:{agent}"
    subnet = subnet_by_node_key.get(node.node_key)
    if subnet:
        return f"subnet:{subnet}"
    cidr = _clean(node.cidr)
    if cidr:
        return f"subnet:{cidr}"
    scope = _ip_scope(node)
    if scope:
        return f"scope:{scope}"
    return "ungrouped"


def group_label(group_key: str, agent_labels: dict[str, str] | None = None) -> str:
    lbl = agent_labels or {}
    if group_key.startswith("agent:"):
        agent_id = group_key[len("agent:"):]
        return lbl.get(agent_id, agent_id)
    if group_key.startswith("subnet:"):
        return group_key[len("subnet:"):]
    if group_key.startswith("scope:"):
        scope = group_key[len("scope:"):]
        return _SCOPE_LABELS.get(scope, scope)
    return "Ungrouped"


def group_type(group_key: str) -> str:
    if group_key.startswith("agent:"):
        return "agent"
    if group_key.startswith("subnet:"):
        return "subnet"
    if group_key.startswith("scope:"):
        return "ip_scope"
    return "ungrouped"


def build_groups(
    nodes: list[Any],
    edges: list[Any],
    *,
    strategy: str = "auto",
    agent_labels: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not nodes:
        return [], []

    effective = strategy if strategy in VALID_STRATEGIES else "auto"
    lbl = agent_labels or {}

    subnet_by_node_key: dict[str, str] = {}
    for edge in edges:
        if _clean(edge.edge_type) == "member_of_subnet":
            subnet_by_node_key[edge.source_node_key] = edge.target_node_key

    node_to_group: dict[str, str] = {}
    for node in nodes:
        node_to_group[node.node_key] = _node_group_key(node, subnet_by_node_key, effective)

    buckets: dict[str, list[Any]] = {}
    for node in nodes:
        buckets.setdefault(node_to_group[node.node_key], []).append(node)

    groups: list[dict[str, Any]] = []
    for gk, bucket_nodes in buckets.items():
        alert_count = sum(int(n.alert_count or 0) for n in bucket_nodes)
        sevs = [_clean(n.severity) or "unknown" for n in bucket_nodes]
        highest_sev = _highest_sev(sevs)
        risk_score = max((int(n.risk_score or 0) for n in bucket_nodes), default=0)
        confidence = max((int(n.confidence or 0) for n in bucket_nodes), default=0)
        stale = all(int(n.is_stale or 0) != 0 for n in bucket_nodes)

        first_seen_vals = [n.first_seen_at for n in bucket_nodes if n.first_seen_at]
        last_seen_vals = [n.last_seen_at for n in bucket_nodes if n.last_seen_at]
        first_seen = min(first_seen_vals) if first_seen_vals else None
        last_seen = max(last_seen_vals) if last_seen_vals else None

        child_keys = [n.node_key for n in bucket_nodes]
        truncated = len(child_keys) > _CHILD_KEY_HARD_CAP
        capped_keys = child_keys[:_CHILD_KEY_HARD_CAP]

        agent_id = next((n.agent_id for n in bucket_nodes if n.agent_id), None)
        cidr = next((n.cidr for n in bucket_nodes if n.cidr), None)

        groups.append({
            "group_key": gk,
            "group_type": group_type(gk),
            "label": group_label(gk, lbl),
            "node_count": len(bucket_nodes),
            "edge_count": 0,
            "alert_count": alert_count,
            "highest_severity": highest_sev,
            "risk_score": risk_score,
            "confidence": confidence,
            "is_stale": stale,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "child_node_keys": capped_keys,
            "child_node_keys_truncated": truncated,
            "metadata": {"agent_id": agent_id, "cidr": cidr},
        })

    group_edge_agg: dict[str, dict[str, Any]] = {}
    group_edge_count: dict[str, int] = {}

    for edge in edges:
        sg = node_to_group.get(edge.source_node_key)
        tg = node_to_group.get(edge.target_node_key)
        if not sg or not tg or sg == tg:
            continue

        group_edge_count[sg] = group_edge_count.get(sg, 0) + 1
        group_edge_count[tg] = group_edge_count.get(tg, 0) + 1

        a, b = (sg, tg) if sg < tg else (tg, sg)
        ek = f"{a}|||{b}"
        edge_sev = _clean(edge.severity) or "unknown"
        fs = getattr(edge, "first_seen_at", None)
        ls = getattr(edge, "last_seen_at", None)

        existing = group_edge_agg.get(ek)
        if existing:
            existing["weight"] = float(existing["weight"]) + float(edge.weight or 1.0)
            existing["alert_count"] = int(existing["alert_count"]) + int(edge.alert_count or 0)
            existing["confidence"] = max(int(existing["confidence"]), int(edge.confidence or 0))
            existing["edge_count"] = int(existing["edge_count"]) + 1
            if _sev_weight(edge_sev) > _sev_weight(existing["highest_severity"]):
                existing["highest_severity"] = edge_sev
            if fs:
                fs_str = fs.isoformat()
                if not existing["first_seen"] or fs_str < existing["first_seen"]:
                    existing["first_seen"] = fs_str
            if ls:
                ls_str = ls.isoformat()
                if not existing["last_seen"] or ls_str > existing["last_seen"]:
                    existing["last_seen"] = ls_str
        else:
            group_edge_agg[ek] = {
                "edge_key": ek,
                "source_group_key": a,
                "target_group_key": b,
                "edge_type": _clean(edge.edge_type) or "observed_flow",
                "weight": float(edge.weight or 1.0),
                "alert_count": int(edge.alert_count or 0),
                "confidence": int(edge.confidence or 0),
                "highest_severity": edge_sev,
                "edge_count": 1,
                "first_seen": fs.isoformat() if fs else None,
                "last_seen": ls.isoformat() if ls else None,
                "metadata": {},
            }

    group_by_key = {g["group_key"]: g for g in groups}
    for gk, cnt in group_edge_count.items():
        if gk in group_by_key:
            group_by_key[gk]["edge_count"] = cnt

    return groups, list(group_edge_agg.values())


def compute_facets(
    nodes: list[Any],
    edges: list[Any],
    groups: list[dict[str, Any]],
) -> dict[str, Any]:
    node_types: dict[str, int] = {}
    severities: dict[str, int] = {}
    ip_scopes: dict[str, int] = {}
    agents: dict[str, int] = {}
    has_alerts_count = 0
    has_exposure_count = 0
    stale_count = 0
    active_count = 0

    for node in nodes:
        nt = _clean(node.node_type) or "unknown"
        node_types[nt] = node_types.get(nt, 0) + 1
        sev = _clean(node.severity) or "unknown"
        severities[sev] = severities.get(sev, 0) + 1
        scope = _ip_scope(node)
        bucket = scope if scope else "unknown"
        ip_scopes[bucket] = ip_scopes.get(bucket, 0) + 1
        if node.agent_id:
            agents[node.agent_id] = agents.get(node.agent_id, 0) + 1
        if int(node.alert_count or 0) > 0:
            has_alerts_count += 1
        if _has_exposure(node):
            has_exposure_count += 1
        if int(node.is_stale or 0) != 0:
            stale_count += 1
        else:
            active_count += 1

    edge_types: dict[str, int] = {}
    for edge in edges:
        et = _clean(edge.edge_type) or "unknown"
        edge_types[et] = edge_types.get(et, 0) + 1

    return {
        "node_types": node_types,
        "edge_types": edge_types,
        "severities": severities,
        "ip_scopes": ip_scopes,
        "agents": agents,
        "group_count": len(groups),
        "has_alerts_count": has_alerts_count,
        "has_exposure_count": has_exposure_count,
        "stale_count": stale_count,
        "active_count": active_count,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }


def apply_exclusive_focus(
    nodes: list[Any],
    edges: list[Any],
    *,
    focused_group_key: str,
    groups: list[dict[str, Any]],
) -> tuple[list[Any], list[Any], bool]:
    group = next((g for g in groups if g["group_key"] == focused_group_key), None)
    if not group:
        return nodes, edges, False

    member_keys: set[str] = set(group["child_node_keys"])

    neighbor_keys: set[str] = set()
    for edge in edges:
        if edge.source_node_key in member_keys:
            neighbor_keys.add(edge.target_node_key)
        if edge.target_node_key in member_keys:
            neighbor_keys.add(edge.source_node_key)
    neighbor_keys -= member_keys

    visible_keys = member_keys | neighbor_keys
    filtered_nodes = [n for n in nodes if n.node_key in visible_keys]
    filtered_edges = [
        e for e in edges
        if e.source_node_key in visible_keys and e.target_node_key in visible_keys
    ]
    return filtered_nodes, filtered_edges, True
