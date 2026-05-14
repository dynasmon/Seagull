from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.network_topology.service import _compute_insights, _compute_visibility
from app.features.network_topology.schemas import TopologyInsightOut, TopologyVisibilityOut

_UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(_UTC)


def _base_metrics() -> dict:
    return {
        "new_internal_hosts": 0,
        "new_external_ips": 0,
        "flow_edge_count": 0,
        "internal_to_internal": 0,
        "internal_to_public": 0,
        "public_to_internal": 0,
        "high_risk_edges": 0,
        "exposed_services": 0,
        "stale_agents": 0,
        "stale_other": 0,
        "noisy_nodes": 0,
        "nodes_with_alerts": 0,
        "docker_node_count": 0,
        "last_flow_at": None,
        "last_alert_at": None,
        "last_inventory_at": None,
    }


class TestComputeInsights:
    def test_empty_metrics_yields_no_activity_insight(self):
        insights = _compute_insights(_base_metrics(), window_minutes=1440)
        ids = [i.id for i in insights]
        assert "no_activity" in ids

    def test_empty_metrics_always_yields_visibility_gaps(self):
        insights = _compute_insights(_base_metrics(), window_minutes=1440)
        groups = {i.group for i in insights}
        assert "visibility_gaps" in groups

    def test_nodes_with_alerts_creates_needs_attention(self):
        metrics = {**_base_metrics(), "nodes_with_alerts": 3}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next((i for i in insights if i.id == "nodes_with_alerts"), None)
        assert item is not None
        assert item.group == "needs_attention"
        assert item.count == 3
        assert item.severity == "medium"

    def test_high_alert_count_raises_severity(self):
        metrics = {**_base_metrics(), "nodes_with_alerts": 10}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next(i for i in insights if i.id == "nodes_with_alerts")
        assert item.severity == "high"

    def test_exposed_services_needs_attention(self):
        metrics = {**_base_metrics(), "exposed_services": 2}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next((i for i in insights if i.id == "exposed_services"), None)
        assert item is not None
        assert item.group == "needs_attention"
        assert item.severity == "high"

    def test_public_to_internal_flows(self):
        metrics = {**_base_metrics(), "public_to_internal": 5}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next((i for i in insights if i.id == "public_to_internal"), None)
        assert item is not None
        assert item.group == "needs_attention"
        assert item.count == 5

    def test_internal_flows_normal_activity(self):
        metrics = {**_base_metrics(), "internal_to_internal": 100, "flow_edge_count": 100}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next((i for i in insights if i.id == "internal_flows"), None)
        assert item is not None
        assert item.group == "normal_activity"
        assert item.count == 100

    def test_no_flow_data_visibility_gap(self):
        insights = _compute_insights(_base_metrics(), window_minutes=1440)
        item = next((i for i in insights if i.id == "no_flow_data"), None)
        assert item is not None
        assert item.group == "visibility_gaps"
        assert item.severity == "medium"

    def test_no_flow_data_gap_absent_when_flows_exist(self):
        metrics = {**_base_metrics(), "flow_edge_count": 50, "internal_to_internal": 50}
        insights = _compute_insights(metrics, window_minutes=1440)
        assert not any(i.id == "no_flow_data" for i in insights)

    def test_stale_agents_needs_attention(self):
        metrics = {**_base_metrics(), "stale_agents": 2}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next((i for i in insights if i.id == "stale_agents"), None)
        assert item is not None
        assert item.group == "needs_attention"
        assert item.count == 2

    def test_docker_context_visibility_gap(self):
        metrics = {**_base_metrics(), "docker_node_count": 3}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next((i for i in insights if i.id == "docker_context"), None)
        assert item is not None
        assert item.group == "visibility_gaps"

    def test_static_gaps_always_present(self):
        insights = _compute_insights(_base_metrics(), window_minutes=1440)
        ids = [i.id for i in insights]
        assert "no_physical_topology" in ids
        assert "no_vlan_info" in ids

    def test_new_external_ips_low_severity_for_small_count(self):
        metrics = {**_base_metrics(), "new_external_ips": 3}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next(i for i in insights if i.id == "new_external_ips")
        assert item.severity == "low"

    def test_new_external_ips_medium_severity_for_large_count(self):
        metrics = {**_base_metrics(), "new_external_ips": 15}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next(i for i in insights if i.id == "new_external_ips")
        assert item.severity == "medium"

    def test_window_label_in_title(self):
        metrics = {**_base_metrics(), "new_internal_hosts": 5, "flow_edge_count": 10, "internal_to_internal": 10}
        insights = _compute_insights(metrics, window_minutes=60)
        item = next((i for i in insights if i.id == "new_internal_hosts"), None)
        assert item is not None
        assert "1h" in item.title

    def test_all_insight_groups_represented_with_full_metrics(self):
        metrics = {
            **_base_metrics(),
            "nodes_with_alerts": 2,
            "flow_edge_count": 50,
            "internal_to_internal": 40,
            "internal_to_public": 10,
            "new_internal_hosts": 3,
            "stale_other": 1,
        }
        insights = _compute_insights(metrics, window_minutes=1440)
        groups = {i.group for i in insights}
        assert "needs_attention" in groups
        assert "normal_activity" in groups
        assert "visibility_gaps" in groups

    def test_stale_topology_segments_visibility_gap(self):
        metrics = {**_base_metrics(), "stale_other": 7}
        insights = _compute_insights(metrics, window_minutes=1440)
        item = next((i for i in insights if i.id == "stale_topology_segments"), None)
        assert item is not None
        assert item.group == "visibility_gaps"
        assert item.count == 7


class TestComputeVisibility:
    def _call(self, *, insight_metrics=None, coverage=None, alert_edge_count=0, exposure_edge_count=0):
        return _compute_visibility(
            insight_metrics=insight_metrics or _base_metrics(),
            coverage=coverage or {},
            alert_edge_count=alert_edge_count,
            exposure_edge_count=exposure_edge_count,
        )

    def test_empty_inputs_returns_valid_object(self):
        vis = self._call()
        assert isinstance(vis, TopologyVisibilityOut)
        assert vis.inventory_coverage == 0.0
        assert not vis.flow_coverage
        assert not vis.alert_coverage

    def test_inventory_coverage_computed_correctly(self):
        coverage = {"agents_projected": 4, "agents_with_inventory": 3}
        vis = self._call(coverage=coverage)
        assert vis.inventory_coverage == pytest.approx(0.75)

    def test_zero_agents_projected_gives_zero_coverage(self):
        vis = self._call(coverage={"agents_projected": 0, "agents_with_inventory": 0})
        assert vis.inventory_coverage == 0.0

    def test_flow_coverage_true_when_flows_exist(self):
        metrics = {**_base_metrics(), "flow_edge_count": 10}
        vis = self._call(insight_metrics=metrics)
        assert vis.flow_coverage is True

    def test_alert_coverage_from_alert_edge_count(self):
        vis = self._call(alert_edge_count=5)
        assert vis.alert_coverage is True

    def test_exposure_coverage_from_exposure_edge_count(self):
        vis = self._call(exposure_edge_count=2)
        assert vis.exposure_coverage is True

    def test_protocol_coverage_requires_flows_and_services(self):
        metrics = {**_base_metrics(), "flow_edge_count": 10}
        coverage_no_services = {"services_projected": 0}
        vis_no = self._call(insight_metrics=metrics, coverage=coverage_no_services)
        assert not vis_no.protocol_coverage

        coverage_with_services = {"services_projected": 3}
        vis_yes = self._call(insight_metrics=metrics, coverage=coverage_with_services)
        assert vis_yes.protocol_coverage

    def test_last_timestamps_forwarded(self):
        now = _now()
        metrics = {**_base_metrics(), "last_flow_at": now, "last_inventory_at": now, "last_alert_at": now}
        vis = self._call(insight_metrics=metrics)
        assert vis.last_event_at is not None
        assert vis.last_inventory_at is not None
        assert vis.last_alert_at is not None

    def test_null_timestamps_remain_none(self):
        vis = self._call()
        assert vis.last_event_at is None
        assert vis.last_inventory_at is None
        assert vis.last_alert_at is None

    def test_known_limitations_always_present(self):
        vis = self._call()
        assert len(vis.known_limitations) >= 4

    def test_docker_limitation_added_when_docker_nodes_exist(self):
        metrics = {**_base_metrics(), "docker_node_count": 2}
        vis = self._call(insight_metrics=metrics)
        assert any("Docker" in lim or "container" in lim.lower() for lim in vis.known_limitations)

    def test_partial_inventory_limitation_added(self):
        coverage = {"agents_projected": 10, "agents_with_inventory": 3}
        vis = self._call(coverage=coverage)
        assert any("partial" in lim.lower() or "incomplete" in lim.lower() for lim in vis.known_limitations)

    def test_no_flow_limitation_added_when_no_flows(self):
        vis = self._call(insight_metrics=_base_metrics())
        assert any("flow" in lim.lower() for lim in vis.known_limitations)

    def test_no_flow_limitation_absent_when_flows_exist(self):
        metrics = {**_base_metrics(), "flow_edge_count": 20}
        vis = self._call(insight_metrics=metrics)
        assert not any("No network flow" in lim for lim in vis.known_limitations)


class TestSummaryApiIncludesInsights:
    def test_summary_endpoint_includes_insights_and_visibility(self, monkeypatch: pytest.MonkeyPatch):
        from fastapi.testclient import TestClient
        from app.features.network_topology.schemas import TopologySummaryOut, TopologyNodeTypeStat
        from app.features.auth.session import PortalPrincipal, get_current_user
        from app.features.network_topology import api as topo_api
        from app.main import app

        app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="test", role="admin")

        monkeypatch.setattr(
            topo_api.service,
            "get_summary",
            lambda _db: TopologySummaryOut(
                total_nodes=10,
                total_edges=5,
                agent_count=2,
                host_count=4,
                subnet_count=1,
                external_ip_count=3,
                service_count=0,
                docker_network_count=0,
                unknown_count=0,
                stale_node_count=0,
                alert_edge_count=1,
                exposure_edge_count=0,
                node_type_breakdown=[TopologyNodeTypeStat(node_type="host", count=4)],
                insights=[
                    TopologyInsightOut(
                        id="nodes_with_alerts",
                        group="needs_attention",
                        severity="medium",
                        title="2 hosts with active alerts",
                        detail="Review alert queue.",
                        count=2,
                    ),
                ],
                visibility=None,
                stale=False,
            ),
        )

        with TestClient(app) as client:
            response = client.get("/network-topology/summary")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        body = response.json()
        assert "insights" in body
        assert len(body["insights"]) == 1
        assert body["insights"][0]["id"] == "nodes_with_alerts"
        assert body["insights"][0]["group"] == "needs_attention"
        assert "visibility" in body
