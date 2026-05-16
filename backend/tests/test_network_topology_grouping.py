from __future__ import annotations

import os
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.network_topology.grouping import (
    VALID_STRATEGIES,
    apply_exclusive_focus,
    build_groups,
    compute_facets,
    group_label,
    group_type,
)

_UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(_UTC)


def _node(
    *,
    node_key: str,
    agent_id: str | None = None,
    node_type: str = "host",
    ip: str | None = None,
    cidr: str | None = None,
    severity: str = "unknown",
    risk_score: int = 0,
    alert_count: int = 0,
    event_count: int = 0,
    confidence: int = 50,
    is_stale: int = 0,
    extra_data: dict | None = None,
):
    n = SimpleNamespace(
        node_key=node_key,
        agent_id=agent_id,
        node_type=node_type,
        ip=ip,
        cidr=cidr,
        severity=severity,
        risk_score=risk_score,
        alert_count=alert_count,
        event_count=event_count,
        confidence=confidence,
        is_stale=is_stale,
        first_seen_at=_now(),
        last_seen_at=_now(),
        extra_data=extra_data or {},
    )
    return n


def _edge(
    *,
    edge_key: str,
    source_node_key: str,
    target_node_key: str,
    edge_type: str = "observed_flow",
    weight: float = 1.0,
    alert_count: int = 0,
    confidence: int = 50,
    severity: str = "unknown",
):
    return SimpleNamespace(
        edge_key=edge_key,
        source_node_key=source_node_key,
        target_node_key=target_node_key,
        edge_type=edge_type,
        weight=weight,
        alert_count=alert_count,
        confidence=confidence,
        severity=severity,
        first_seen_at=_now(),
        last_seen_at=_now(),
    )


class TestGroupKeyStability:
    def test_agent_group_key_is_stable(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="agent-abc"),
            _node(node_key="n2", agent_id="agent-abc"),
        ]
        groups1, _ = build_groups(nodes, [], strategy="agent")
        groups2, _ = build_groups(nodes, [], strategy="agent")
        assert len(groups1) == 1
        assert groups1[0]["group_key"] == groups2[0]["group_key"]
        assert groups1[0]["group_key"] == "agent:agent-abc"

    def test_subnet_group_key_is_stable(self) -> None:
        nodes = [
            _node(node_key="n1", cidr="10.0.0.0/24"),
            _node(node_key="n2", cidr="10.0.0.0/24"),
        ]
        groups1, _ = build_groups(nodes, [], strategy="subnet")
        groups2, _ = build_groups(nodes, [], strategy="subnet")
        assert groups1[0]["group_key"] == groups2[0]["group_key"]
        assert groups1[0]["group_key"] == "subnet:10.0.0.0/24"

    def test_scope_group_key_is_stable(self) -> None:
        nodes = [
            _node(node_key="n1", extra_data={"ip_scope": "private_address"}),
        ]
        groups1, _ = build_groups(nodes, [], strategy="ip_scope")
        groups2, _ = build_groups(nodes, [], strategy="ip_scope")
        assert groups1[0]["group_key"] == groups2[0]["group_key"]
        assert groups1[0]["group_key"] == "scope:private_address"


class TestGroupingByAgent:
    def test_nodes_grouped_by_agent(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a1"),
            _node(node_key="n3", agent_id="a2"),
        ]
        groups, _ = build_groups(nodes, [], strategy="agent")
        keys = {g["group_key"] for g in groups}
        assert keys == {"agent:a1", "agent:a2"}
        a1_group = next(g for g in groups if g["group_key"] == "agent:a1")
        assert a1_group["node_count"] == 2

    def test_node_without_agent_goes_to_ungrouped(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id=None),
        ]
        groups, _ = build_groups(nodes, [], strategy="agent")
        keys = {g["group_key"] for g in groups}
        assert "ungrouped" in keys

    def test_agent_label_applied(self) -> None:
        nodes = [_node(node_key="n1", agent_id="agent-abc")]
        groups, _ = build_groups(nodes, [], strategy="agent", agent_labels={"agent-abc": "My Agent"})
        assert groups[0]["label"] == "My Agent"

    def test_unknown_agent_uses_id_as_label(self) -> None:
        nodes = [_node(node_key="n1", agent_id="agent-xyz")]
        groups, _ = build_groups(nodes, [], strategy="agent")
        assert groups[0]["label"] == "agent-xyz"


class TestGroupingBySubnet:
    def test_nodes_grouped_via_member_of_subnet_edge(self) -> None:
        nodes = [
            _node(node_key="h1"),
            _node(node_key="h2"),
            _node(node_key="subnet:10.0.0.0/24", node_type="subnet", cidr="10.0.0.0/24"),
        ]
        edges = [
            _edge(edge_key="e1", source_node_key="h1", target_node_key="subnet:10.0.0.0/24", edge_type="member_of_subnet"),
            _edge(edge_key="e2", source_node_key="h2", target_node_key="subnet:10.0.0.0/24", edge_type="member_of_subnet"),
        ]
        groups, _ = build_groups(nodes, edges, strategy="subnet")
        subnet_group = next((g for g in groups if g["group_key"].startswith("subnet:")), None)
        assert subnet_group is not None
        assert subnet_group["node_count"] >= 2

    def test_node_with_cidr_grouped_by_cidr(self) -> None:
        nodes = [_node(node_key="n1", cidr="192.168.1.0/24")]
        groups, _ = build_groups(nodes, [], strategy="subnet")
        assert groups[0]["group_key"] == "subnet:192.168.1.0/24"


class TestGroupingByIpScope:
    def test_nodes_grouped_by_scope(self) -> None:
        nodes = [
            _node(node_key="n1", extra_data={"ip_scope": "private_address"}),
            _node(node_key="n2", extra_data={"ip_scope": "private_address"}),
            _node(node_key="n3", extra_data={"ip_scope": "public_internet"}),
        ]
        groups, _ = build_groups(nodes, [], strategy="ip_scope")
        keys = {g["group_key"] for g in groups}
        assert "scope:private_address" in keys
        assert "scope:public_internet" in keys

    def test_scope_label_resolved(self) -> None:
        nodes = [_node(node_key="n1", extra_data={"ip_scope": "public_internet"})]
        groups, _ = build_groups(nodes, [], strategy="ip_scope")
        assert groups[0]["label"] == "Public Internet"


class TestAutoGrouping:
    def test_auto_prefers_agent_over_subnet(self) -> None:
        nodes = [_node(node_key="n1", agent_id="a1", cidr="10.0.0.0/24")]
        groups, _ = build_groups(nodes, [], strategy="auto")
        assert groups[0]["group_key"] == "agent:a1"

    def test_auto_falls_back_to_subnet(self) -> None:
        nodes = [_node(node_key="n1", agent_id=None, cidr="10.0.0.0/24")]
        groups, _ = build_groups(nodes, [], strategy="auto")
        assert groups[0]["group_key"] == "subnet:10.0.0.0/24"

    def test_auto_falls_back_to_scope(self) -> None:
        nodes = [_node(node_key="n1", agent_id=None, cidr=None, extra_data={"ip_scope": "public_internet"})]
        groups, _ = build_groups(nodes, [], strategy="auto")
        assert groups[0]["group_key"] == "scope:public_internet"

    def test_auto_falls_back_to_ungrouped(self) -> None:
        nodes = [_node(node_key="n1", agent_id=None, cidr=None)]
        groups, _ = build_groups(nodes, [], strategy="auto")
        assert groups[0]["group_key"] == "ungrouped"

    def test_invalid_strategy_treated_as_auto(self) -> None:
        nodes = [_node(node_key="n1", agent_id="a1")]
        groups_auto, _ = build_groups(nodes, [], strategy="auto")
        groups_invalid, _ = build_groups(nodes, [], strategy="INVALID")
        assert groups_auto[0]["group_key"] == groups_invalid[0]["group_key"]

    def test_auto_no_location_site_metadata(self) -> None:
        nodes = [_node(node_key="n1", agent_id="a1", extra_data={})]
        groups, _ = build_groups(nodes, [], strategy="auto")
        assert groups[0]["group_key"] == "agent:a1"


class TestGroupEdgeAggregation:
    def test_inter_group_edges_aggregated(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a2"),
        ]
        edges = [
            _edge(edge_key="e1", source_node_key="n1", target_node_key="n2", edge_type="observed_flow", weight=2.0, alert_count=1),
            _edge(edge_key="e2", source_node_key="n1", target_node_key="n2", edge_type="observed_flow", weight=3.0, alert_count=2),
        ]
        _, group_edges = build_groups(nodes, edges, strategy="agent")
        assert len(group_edges) == 1
        ge = group_edges[0]
        assert ge["weight"] == pytest.approx(5.0)
        assert ge["alert_count"] == 3
        assert ge["edge_count"] == 2

    def test_intra_group_edges_not_included(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a1"),
        ]
        edges = [_edge(edge_key="e1", source_node_key="n1", target_node_key="n2")]
        _, group_edges = build_groups(nodes, edges, strategy="agent")
        assert len(group_edges) == 0

    def test_group_edge_key_is_directionally_normalized(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a2"),
        ]
        edges_ab = [_edge(edge_key="e1", source_node_key="n1", target_node_key="n2")]
        edges_ba = [_edge(edge_key="e2", source_node_key="n2", target_node_key="n1")]
        _, ge_ab = build_groups(nodes, edges_ab, strategy="agent")
        _, ge_ba = build_groups(nodes, edges_ba, strategy="agent")
        assert ge_ab[0]["edge_key"] == ge_ba[0]["edge_key"]

    def test_group_edge_count_updates_group(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a2"),
        ]
        edges = [_edge(edge_key="e1", source_node_key="n1", target_node_key="n2")]
        groups, _ = build_groups(nodes, edges, strategy="agent")
        g1 = next(g for g in groups if g["group_key"] == "agent:a1")
        assert g1["edge_count"] == 1


class TestChildNodeKeysCap:
    def test_cap_applied_when_over_limit(self) -> None:
        nodes = [_node(node_key=f"n{i}", agent_id="a1") for i in range(250)]
        groups, _ = build_groups(nodes, [], strategy="agent")
        assert groups[0]["node_count"] == 250
        assert len(groups[0]["child_node_keys"]) == 200
        assert groups[0]["child_node_keys_truncated"] is True

    def test_no_truncation_when_under_limit(self) -> None:
        nodes = [_node(node_key=f"n{i}", agent_id="a1") for i in range(10)]
        groups, _ = build_groups(nodes, [], strategy="agent")
        assert groups[0]["child_node_keys_truncated"] is False
        assert len(groups[0]["child_node_keys"]) == 10


class TestComputeFacets:
    def test_facet_counts_node_types(self) -> None:
        nodes = [
            _node(node_key="n1", node_type="host"),
            _node(node_key="n2", node_type="host"),
            _node(node_key="n3", node_type="agent"),
        ]
        facets = compute_facets(nodes, [], [])
        assert facets["node_types"]["host"] == 2
        assert facets["node_types"]["agent"] == 1

    def test_facet_counts_edge_types(self) -> None:
        nodes = [_node(node_key="n1"), _node(node_key="n2")]
        edges = [
            _edge(edge_key="e1", source_node_key="n1", target_node_key="n2", edge_type="observed_flow"),
            _edge(edge_key="e2", source_node_key="n1", target_node_key="n2", edge_type="alert_related"),
        ]
        facets = compute_facets(nodes, edges, [])
        assert facets["edge_types"]["observed_flow"] == 1
        assert facets["edge_types"]["alert_related"] == 1

    def test_facet_has_alerts_count(self) -> None:
        nodes = [
            _node(node_key="n1", alert_count=2),
            _node(node_key="n2", alert_count=0),
        ]
        facets = compute_facets(nodes, [], [])
        assert facets["has_alerts_count"] == 1

    def test_facet_has_exposure_count(self) -> None:
        nodes = [
            _node(node_key="n1", extra_data={"exposure_asset_key": "asset-1"}),
            _node(node_key="n2", extra_data={}),
        ]
        facets = compute_facets(nodes, [], [])
        assert facets["has_exposure_count"] == 1

    def test_facet_stale_count(self) -> None:
        nodes = [
            _node(node_key="n1", is_stale=1),
            _node(node_key="n2", is_stale=0),
        ]
        facets = compute_facets(nodes, [], [])
        assert facets["stale_count"] == 1

    def test_facet_active_count(self) -> None:
        nodes = [
            _node(node_key="n1", is_stale=0),
            _node(node_key="n2", is_stale=1),
            _node(node_key="n3", is_stale=0),
        ]
        facets = compute_facets(nodes, [], [])
        assert facets["active_count"] == 2

    def test_facet_group_count(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a2"),
        ]
        raw_groups, _ = build_groups(nodes, [], strategy="agent")
        facets = compute_facets(nodes, [], raw_groups)
        assert facets["group_count"] == 2

    def test_ip_scope_unknown_bucket_for_missing_scope(self) -> None:
        nodes = [
            _node(node_key="n1", extra_data={}),
            _node(node_key="n2", extra_data={"ip_scope": "private_address"}),
        ]
        facets = compute_facets(nodes, [], [])
        assert facets["ip_scopes"].get("unknown", 0) == 1
        assert facets["ip_scopes"].get("private_address", 0) == 1

    def test_ip_scope_all_missing_goes_to_unknown(self) -> None:
        nodes = [_node(node_key=f"n{i}", extra_data={}) for i in range(3)]
        facets = compute_facets(nodes, [], [])
        assert facets["ip_scopes"].get("unknown", 0) == 3


class TestApplyExclusiveFocus:
    def test_filters_to_member_nodes_plus_neighbors(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a1"),
            _node(node_key="n3", agent_id="a2"),
            _node(node_key="n4", agent_id="a3"),
        ]
        edges = [
            _edge(edge_key="e1", source_node_key="n1", target_node_key="n3"),
        ]
        raw_groups, _ = build_groups(nodes, edges, strategy="agent")
        filtered_nodes, filtered_edges, applied = apply_exclusive_focus(
            nodes, edges, focused_group_key="agent:a1", groups=raw_groups
        )
        assert applied is True
        filtered_keys = {n.node_key for n in filtered_nodes}
        assert "n1" in filtered_keys
        assert "n2" in filtered_keys
        assert "n3" in filtered_keys  # first-hop neighbor
        assert "n4" not in filtered_keys

    def test_returns_false_when_group_not_found(self) -> None:
        nodes = [_node(node_key="n1", agent_id="a1")]
        raw_groups, _ = build_groups(nodes, [], strategy="agent")
        returned_nodes, returned_edges, applied = apply_exclusive_focus(
            nodes, [], focused_group_key="agent:nonexistent", groups=raw_groups
        )
        assert applied is False
        assert returned_nodes is nodes
        assert returned_edges == []

    def test_edges_filtered_to_visible_keys(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a2"),
            _node(node_key="n3", agent_id="a3"),
        ]
        edges = [
            _edge(edge_key="e1", source_node_key="n2", target_node_key="n3"),
        ]
        raw_groups, _ = build_groups(nodes, edges, strategy="agent")
        _, filtered_edges, applied = apply_exclusive_focus(
            nodes, edges, focused_group_key="agent:a1", groups=raw_groups
        )
        assert applied is True
        assert len(filtered_edges) == 0

    def test_intra_group_member_edge_included(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a1"),
        ]
        edges = [_edge(edge_key="e1", source_node_key="n1", target_node_key="n2")]
        raw_groups, _ = build_groups(nodes, edges, strategy="agent")
        _, filtered_edges, applied = apply_exclusive_focus(
            nodes, edges, focused_group_key="agent:a1", groups=raw_groups
        )
        assert applied is True
        assert len(filtered_edges) == 1

    def test_member_to_neighbor_edge_included(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a2"),
        ]
        edges = [_edge(edge_key="e1", source_node_key="n1", target_node_key="n2")]
        raw_groups, _ = build_groups(nodes, edges, strategy="agent")
        _, filtered_edges, applied = apply_exclusive_focus(
            nodes, edges, focused_group_key="agent:a1", groups=raw_groups
        )
        assert applied is True
        assert len(filtered_edges) == 1

    def test_outside_to_outside_edge_excluded(self) -> None:
        nodes = [
            _node(node_key="n1", agent_id="a1"),
            _node(node_key="n2", agent_id="a2"),
            _node(node_key="n3", agent_id="a3"),
        ]
        edges = [
            _edge(edge_key="e1", source_node_key="n2", target_node_key="n3"),
        ]
        raw_groups, _ = build_groups(nodes, edges, strategy="agent")
        _, filtered_edges, applied = apply_exclusive_focus(
            nodes, edges, focused_group_key="agent:a1", groups=raw_groups
        )
        assert applied is True
        assert len(filtered_edges) == 0


class TestGroupLabelAndType:
    def test_group_type_agent(self) -> None:
        assert group_type("agent:abc") == "agent"

    def test_group_type_subnet(self) -> None:
        assert group_type("subnet:10.0.0.0/24") == "subnet"

    def test_group_type_scope(self) -> None:
        assert group_type("scope:private_address") == "ip_scope"

    def test_group_type_ungrouped(self) -> None:
        assert group_type("ungrouped") == "ungrouped"

    def test_group_label_uses_agent_labels_map(self) -> None:
        assert group_label("agent:my-id", {"my-id": "My Agent"}) == "My Agent"

    def test_group_label_scope_mapped(self) -> None:
        assert group_label("scope:public_internet") == "Public Internet"

    def test_group_label_ungrouped(self) -> None:
        assert group_label("ungrouped") == "Ungrouped"


class TestValidStrategies:
    def test_all_strategies_present(self) -> None:
        assert VALID_STRATEGIES == {"auto", "agent", "subnet", "ip_scope"}

    def test_empty_nodes_returns_empty(self) -> None:
        groups, edges = build_groups([], [], strategy="auto")
        assert groups == []
        assert edges == []
