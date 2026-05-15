"""Unit tests for the topology projector.

All repository I/O is intercepted at the repository boundary so no database
is required.  Each test drives project_topology (or a sub-phase helper) with
model fixtures and asserts what nodes / edges would have been written.
"""
from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.agents.models import AgentModel
from app.features.alerts.models import AlertModel
from app.features.exposure.models import ExposureAssetPostureModel
from app.features.inventory.models import AgentInventoryLatestModel
from app.features.network_topology import projector as proj
from app.features.network_topology import repository as repo

_UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(_UTC)


# ── Fake DB session helpers ───────────────────────────────────────────────────

class _FakeScalars:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items

    def first(self):
        return self._items[0] if self._items else None

    def one(self):
        return self._items[0]


class _FakeResult:
    def __init__(self, rows=None, scalar_val=None):
        self._rows = rows or []
        self._scalar_val = scalar_val

    def scalars(self):
        return _FakeScalars(self._rows)

    def all(self):
        return self._rows

    def scalar(self):
        return self._scalar_val


def _make_agent(agent_id: str = "agent-1", display_name: str = "Host-1") -> AgentModel:
    a = AgentModel()
    a.agent_id = agent_id
    a.display_name = display_name
    a.is_revoked = False
    a.last_seen_at = _now()
    a.created_at = _now()
    return a


def _make_inventory(
    agent_id: str = "agent-1",
    hostname: str = "host-1",
    ip_addresses: list[str] | None = None,
    interfaces: list[dict] | None = None,
    neighbors: list[dict] | None = None,
    routes: list[dict] | None = None,
) -> AgentInventoryLatestModel:
    inv = AgentInventoryLatestModel()
    inv.agent_id = agent_id
    inv.os = {"hostname": hostname, "ip_addresses": ip_addresses or []}
    inv.extra = {}
    if interfaces is not None:
        inv.extra = {
            "network_context": {
                "interfaces": interfaces,
                "neighbors": neighbors or [],
                "routes": routes or [],
                "source": "host_observed",
            }
        }
    inv.updated_at = _now()
    inv.collected_at = _now()
    return inv


def _make_alert(
    src_ip: str = "10.0.0.10",
    dst_ip: str = "1.2.3.4",
    dst_port: int = 443,
    severity: str = "high",
) -> AlertModel:
    a = AlertModel()
    a.src_ip = src_ip
    a.dst_ip = dst_ip
    a.dst_port = dst_port
    a.severity = severity
    a.created_at = _now()
    return a


def _make_posture(
    agent_id: str = "agent-1",
    asset_key: str = "asset:agent-1",
    severity: str = "medium",
    risk_score: int = 40,
) -> ExposureAssetPostureModel:
    p = ExposureAssetPostureModel()
    p.agent_id = agent_id
    p.asset_key = asset_key
    p.display_name = asset_key
    p.severity = severity
    p.risk_score = risk_score
    p.confidence = 80
    p.last_seen_at = _now()
    return p


class _RecordingDB:
    """Intercepts upsert_node / upsert_edge calls and records arguments."""

    def __init__(self):
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self._query_map: dict[type, list] = defaultdict(list)

    def register_query(self, model_cls, rows):
        self._query_map[model_cls] = rows

    def execute(self, stmt):
        # Determine which model is being queried from the stmt columns/froms
        for cls, rows in self._query_map.items():
            if hasattr(stmt, "froms"):
                for f in getattr(stmt, "froms", []):
                    tbl = getattr(f, "name", None) or getattr(f, "__tablename__", None)
                    if tbl == getattr(cls, "__tablename__", None):
                        return _FakeResult(rows=rows, scalar_val=len(rows))
            # For aggregate queries (count stale)
            if hasattr(stmt, "_raw_columns"):
                return _FakeResult(scalar_val=0)
        return _FakeResult(rows=[], scalar_val=0)


# ── Projector sub-function helpers ────────────────────────────────────────────

def _run_agents(agents, *, now=None):
    """Run _project_agents with mocked repository."""
    now = now or _now()
    written_nodes: list[dict] = []

    def fake_db_execute(stmt):
        return _FakeResult(rows=agents)

    db = MagicMock()
    db.execute.return_value = _FakeResult(rows=agents)

    with patch.object(repo, "upsert_node", side_effect=lambda db, **kw: written_nodes.append(kw)) as _u, \
         patch.object(repo, "upsert_edge"):
        coverage_mock = MagicMock()
        coverage_mock.agents_projected = 0
        result = proj._project_agents(db, now=now, coverage=coverage_mock)

    return result, written_nodes


def _run_inventory(inv_rows, *, agent_nodes=None, cidrs=None, now=None):
    """Run _project_inventory with mocked repository."""
    now = now or _now()
    agent_nodes = agent_nodes or {}
    written_nodes: list[dict] = []
    written_edges: list[dict] = []

    db = MagicMock()
    db.execute.return_value = _FakeResult(rows=inv_rows)

    coverage_mock = MagicMock()
    coverage_mock.agents_with_inventory = 0
    coverage_mock.interfaces_extracted = 0
    coverage_mock.subnets_inferred = 0

    with patch.object(repo, "upsert_node", side_effect=lambda db, **kw: written_nodes.append(kw)), \
         patch.object(repo, "upsert_edge", side_effect=lambda db, **kw: written_edges.append(kw)):
        proj._project_inventory(
            db,
            now=now,
            cidrs=cidrs,
            coverage=coverage_mock,
            agent_nodes=agent_nodes,
        )

    return written_nodes, written_edges


def _run_alerts(alerts, *, cidrs=None, now=None):
    now = now or _now()
    written_nodes: list[dict] = []
    written_edges: list[dict] = []
    coverage_mock = MagicMock()
    coverage_mock.alert_edges_added = 0

    # Build fake rows as tuples (src_ip, dst_ip, dst_port, severity, created_at)
    rows = [
        (a.src_ip, a.dst_ip, a.dst_port, a.severity, a.created_at)
        for a in alerts
    ]

    db = MagicMock()
    db.execute.return_value = _FakeResult(rows=rows)

    with patch.object(repo, "upsert_node", side_effect=lambda db, **kw: written_nodes.append(kw)), \
         patch.object(repo, "upsert_edge", side_effect=lambda db, **kw: written_edges.append(kw)):
        proj._project_alert_edges(db, now=now, cidrs=cidrs, coverage=coverage_mock)

    return written_nodes, written_edges, coverage_mock


# ── Agent projection ──────────────────────────────────────────────────────────

def test_agent_node_key_format():
    agents = [_make_agent("agent-abc")]
    result, nodes = _run_agents(agents)
    assert "agent-abc" in result
    assert result["agent-abc"] == "topo:agent:agent-abc"


def test_agent_node_type_and_confidence():
    agents = [_make_agent("agent-1")]
    _, nodes = _run_agents(agents)
    node = nodes[0]
    assert node["node_type"] == "agent"
    assert node["confidence"] == 95


def test_multiple_agents_all_projected():
    agents = [_make_agent(f"agent-{i}") for i in range(5)]
    result, nodes = _run_agents(agents)
    assert len(result) == 5
    assert len(nodes) == 5


# ── Inventory: network_context path ──────────────────────────────────────────

def test_network_context_interface_key_uses_name():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
    )
    nodes, _ = _run_inventory([inv], agent_nodes={"agent-1": "topo:agent:agent-1"})
    keys = [n["node_key"] for n in nodes]
    assert "topo:interface:agent-1:eth0" in keys


def test_network_context_host_key_uses_primary_ip():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
    )
    nodes, _ = _run_inventory([inv], agent_nodes={"agent-1": "topo:agent:agent-1"})
    keys = [n["node_key"] for n in nodes]
    assert "topo:host:agent-1:10.0.1.5" in keys


def test_network_context_subnet_derived_from_cidr():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
    )
    nodes, _ = _run_inventory([inv])
    subnet_nodes = [n for n in nodes if n["node_type"] == "subnet"]
    assert len(subnet_nodes) == 1
    assert subnet_nodes[0]["cidr"] == "10.0.1.0/24"
    assert subnet_nodes[0]["node_key"] == "topo:subnet:10.0.1.0/24"


def test_network_context_loopback_skipped_for_subnet():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[
            {"name": "lo", "ips": ["127.0.0.1"], "cidrs": ["127.0.0.1/8"], "is_loopback": True},
            {"name": "eth0", "ips": ["10.0.0.5"], "cidrs": ["10.0.0.5/24"]},
        ],
    )
    nodes, _ = _run_inventory([inv])
    subnet_nodes = [n for n in nodes if n["node_type"] == "subnet"]
    # Only eth0 should produce a subnet (loopback skipped)
    assert len(subnet_nodes) == 1
    assert "10.0.0.0/24" in subnet_nodes[0]["cidr"]


def test_network_context_same_agent_edge():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
    )
    _, edges = _run_inventory([inv], agent_nodes={"agent-1": "topo:agent:agent-1"})
    types = [e["edge_type"] for e in edges]
    assert "same_agent" in types


def test_network_context_owns_interface_edge():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
    )
    _, edges = _run_inventory([inv])
    types = [e["edge_type"] for e in edges]
    assert "owns_interface" in types


def test_network_context_member_of_subnet_edge():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
    )
    _, edges = _run_inventory([inv])
    types = [e["edge_type"] for e in edges]
    assert "member_of_subnet" in types


def test_network_context_neighbor_projects_host_and_edge():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
        neighbors=[{"ip": "10.0.1.20", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0", "state": "reachable"}],
    )
    nodes, edges = _run_inventory([inv])
    assert any(n["node_key"] == "topo:host:10.0.1.20" for n in nodes)
    assert any(e["edge_type"] == "inferred_relationship" for e in edges)
    assert any(
        e["edge_type"] == "member_of_subnet" and e["source_node_key"] == "topo:host:10.0.1.20"
        for e in edges
    )


def test_network_context_route_projects_gateway_edge():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[{"name": "eth0", "ips": ["10.0.1.5"], "cidrs": ["10.0.1.5/24"]}],
        routes=[{"destination": "0.0.0.0/0", "gateway": "10.0.1.1", "interface": "eth0", "family": "ipv4"}],
    )
    nodes, edges = _run_inventory([inv])
    assert any(n["node_key"] == "topo:gateway:10.0.1.1" for n in nodes)
    assert any(e["edge_type"] == "route_next_hop" for e in edges)


# ── Inventory: ip_addresses fallback path ────────────────────────────────────

def test_fallback_interface_key_uses_ip():
    inv = _make_inventory(agent_id="agent-1", hostname="host-1", ip_addresses=["192.168.5.20"])
    nodes, _ = _run_inventory([inv])
    keys = [n["node_key"] for n in nodes]
    assert "topo:interface:agent-1:192.168.5.20" in keys


def test_fallback_host_key_uses_hostname():
    inv = _make_inventory(agent_id="agent-1", hostname="myhost", ip_addresses=["192.168.5.20"])
    nodes, _ = _run_inventory([inv])
    keys = [n["node_key"] for n in nodes]
    assert "topo:host:agent-1:myhost" in keys


def test_fallback_subnet_inferred_from_ip():
    inv = _make_inventory(agent_id="agent-1", hostname="host-1", ip_addresses=["10.1.2.50"])
    nodes, _ = _run_inventory([inv])
    subnet_nodes = [n for n in nodes if n["node_type"] == "subnet"]
    assert len(subnet_nodes) == 1
    assert subnet_nodes[0]["cidr"] == "10.1.2.0/24"


def test_fallback_no_subnet_for_empty_ip_list():
    inv = _make_inventory(agent_id="agent-1", hostname="host-1", ip_addresses=[])
    nodes, _ = _run_inventory([inv])
    subnet_nodes = [n for n in nodes if n["node_type"] == "subnet"]
    assert len(subnet_nodes) == 0


# ── Alert edge projection ─────────────────────────────────────────────────────

def test_alert_creates_two_ip_nodes():
    alerts = [_make_alert(src_ip="10.0.0.1", dst_ip="8.8.8.8")]
    nodes, _, _ = _run_alerts(alerts)
    assert len(nodes) == 2


def test_alert_creates_alert_related_edge():
    alerts = [_make_alert()]
    _, edges, _ = _run_alerts(alerts)
    assert any(e["edge_type"] == "alert_related" for e in edges)


def test_alert_edge_severity_propagates():
    alerts = [_make_alert(severity="critical")]
    _, edges, _ = _run_alerts(alerts)
    edge = next(e for e in edges if e["edge_type"] == "alert_related")
    assert edge["severity"] == "critical"
    assert edge["weight"] == 3.0


def test_alert_external_ip_classified_as_external():
    alerts = [_make_alert(src_ip="10.0.0.1", dst_ip="1.1.1.1")]
    nodes, _, _ = _run_alerts(alerts)
    external_nodes = [n for n in nodes if n["node_type"] == "external_ip"]
    assert len(external_nodes) >= 1
    assert any(n["ip"] == "1.1.1.1" for n in external_nodes)


def test_alert_internal_ip_classified_as_host():
    alerts = [_make_alert(src_ip="192.168.1.10", dst_ip="8.8.8.8")]
    nodes, _, _ = _run_alerts(alerts)
    internal_nodes = [n for n in nodes if n["ip"] == "192.168.1.10"]
    assert internal_nodes[0]["node_type"] == "host"


def test_alert_increments_coverage_count():
    alerts = [_make_alert(), _make_alert(src_ip="10.0.0.2")]
    _, _, coverage = _run_alerts(alerts)
    assert coverage.alert_edges_added == 2


# ── Severity helpers ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("sev,expected", [
    ("critical", 90),
    ("high", 70),
    ("medium", 50),
    ("low", 30),
    ("informational", 10),
    ("unknown", 0),
])
def test_sev_to_score(sev, expected):
    assert proj._sev_to_score(sev) == expected


@pytest.mark.parametrize("sev,expected", [
    ("critical", 3.0),
    ("high", 2.0),
    ("medium", 1.5),
    ("low", 1.0),
    ("informational", 0.5),
    ("other", 1.0),
])
def test_sev_weight(sev, expected):
    assert proj._sev_weight(sev) == expected


# ── Node/edge key helpers ─────────────────────────────────────────────────────

def test_node_key_short():
    assert proj._node_key("agent", "abc") == "topo:agent:abc"


def test_node_key_truncated_on_long_input():
    long_id = "x" * 300
    key = proj._node_key("host", long_id)
    assert len(key) <= 200
    assert key.startswith("topo:host:")


def test_edge_key_short():
    key = proj._edge_key("same_agent", "topo:agent:a", "topo:host:b")
    assert key == "same_agent::topo:agent:a::topo:host:b"


def test_edge_key_truncated_on_long_input():
    src = "topo:agent:" + "a" * 200
    dst = "topo:host:" + "b" * 200
    key = proj._edge_key("same_agent", src, dst)
    assert len(key) <= 250
    assert key.startswith("same_agent::")


def test_flow_edge_key_includes_port_and_proto():
    k1 = proj._flow_edge_key("topo:host:10.0.0.1", "topo:host:10.0.0.2", 443, "tcp")
    k2 = proj._flow_edge_key("topo:host:10.0.0.1", "topo:host:10.0.0.2", 80, "tcp")
    assert k1 != k2


def test_flow_edge_key_same_endpoints_same_port_equal():
    k1 = proj._flow_edge_key("topo:host:a", "topo:host:b", 443, "tcp")
    k2 = proj._flow_edge_key("topo:host:a", "topo:host:b", 443, "tcp")
    assert k1 == k2


# ── Subnet CIDR derivation ────────────────────────────────────────────────────

def test_network_from_iface_cidrs_derives_network():
    result = proj._network_from_iface_cidrs(["10.0.1.5/24"], "10.0.1.5")
    assert result == "10.0.1.0/24"


def test_network_from_iface_cidrs_falls_back_to_infer():
    result = proj._network_from_iface_cidrs([], "172.16.5.10")
    assert result == "172.16.5.0/24"


def test_network_from_iface_cidrs_skips_loopback():
    result = proj._network_from_iface_cidrs(["127.0.0.1/8"], "127.0.0.1")
    # Loopback should be skipped; fallback infer_subnet_cidr returns /24
    assert result == "127.0.0.0/24"


def test_network_from_iface_cidrs_invalid_cidr_falls_back():
    result = proj._network_from_iface_cidrs(["not-a-cidr"], "10.0.2.1")
    assert result == "10.0.2.0/24"


# ── Stale agent detection ─────────────────────────────────────────────────────

def test_is_stale_agent_old():
    from datetime import timedelta
    old = datetime.now(_UTC) - timedelta(days=10)
    assert proj._is_stale_agent(old, datetime.now(_UTC)) is True


def test_is_stale_agent_recent():
    assert proj._is_stale_agent(datetime.now(_UTC), datetime.now(_UTC)) is False


def test_is_stale_agent_none():
    assert proj._is_stale_agent(None, datetime.now(_UTC)) is True


# ── Subnet deduplication ──────────────────────────────────────────────────────

def test_same_subnet_not_duplicated_across_interfaces():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[
            {"name": "eth0", "ips": ["10.0.0.5"], "cidrs": ["10.0.0.5/24"]},
            {"name": "eth1", "ips": ["10.0.0.6"], "cidrs": ["10.0.0.6/24"]},
        ],
    )
    nodes, _ = _run_inventory([inv])
    subnet_nodes = [n for n in nodes if n["node_type"] == "subnet"]
    cidr_values = [n["cidr"] for n in subnet_nodes]
    assert cidr_values.count("10.0.0.0/24") == 1


def test_different_subnets_both_created():
    inv = _make_inventory(
        agent_id="agent-1",
        hostname="host-1",
        interfaces=[
            {"name": "eth0", "ips": ["10.0.0.5"], "cidrs": ["10.0.0.5/24"]},
            {"name": "eth1", "ips": ["192.168.1.10"], "cidrs": ["192.168.1.10/24"]},
        ],
    )
    nodes, _ = _run_inventory([inv])
    subnet_nodes = [n for n in nodes if n["node_type"] == "subnet"]
    assert len(subnet_nodes) == 2
