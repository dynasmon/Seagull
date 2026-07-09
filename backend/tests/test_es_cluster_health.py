from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from app.core.integrations import es as es_integration
from app.core.integrations.es import _evaluate_cluster_state, _resolve_expected_status


def _health(status: str, nodes: int = 3, unassigned: int = 0) -> Dict[str, Any]:
    return {
        "status": status,
        "number_of_nodes": nodes,
        "number_of_data_nodes": nodes,
        "active_shards_percent_as_number": 100.0 if status == "green" else 80.0,
        "unassigned_shards": unassigned,
        "relocating_shards": 0,
        "initializing_shards": 0,
    }


def test_resolve_expected_status() -> None:
    assert _resolve_expected_status("auto", 1) == "yellow"
    assert _resolve_expected_status("auto", 3) == "green"
    assert _resolve_expected_status("auto", None) == "yellow"
    assert _resolve_expected_status("green", 1) == "green"
    assert _resolve_expected_status("yellow", 3) == "yellow"
    assert _resolve_expected_status("", 3) == "green"


def test_green_cluster_is_not_below_expected() -> None:
    report, since = _evaluate_cluster_state(
        _health("green"),
        expected_configured="auto",
        alert_after_seconds=900.0,
        below_since=None,
        now=1000.0,
    )
    assert report["status"] == "green"
    assert report["expected"] == "green"
    assert report["below_expected"] is False
    assert report["alert"] is False
    assert since is None


def test_single_node_yellow_is_expected_under_auto() -> None:
    report, since = _evaluate_cluster_state(
        _health("yellow", nodes=1, unassigned=4),
        expected_configured="auto",
        alert_after_seconds=900.0,
        below_since=None,
        now=1000.0,
    )
    assert report["expected"] == "yellow"
    assert report["below_expected"] is False
    assert report["alert"] is False
    assert since is None


def test_multi_node_yellow_alerts_only_after_threshold() -> None:
    report, since = _evaluate_cluster_state(
        _health("yellow", unassigned=6),
        expected_configured="auto",
        alert_after_seconds=900.0,
        below_since=None,
        now=1000.0,
    )
    assert report["expected"] == "green"
    assert report["below_expected"] is True
    assert report["alert"] is False
    assert since == 1000.0

    report, since = _evaluate_cluster_state(
        _health("yellow", unassigned=6),
        expected_configured="auto",
        alert_after_seconds=900.0,
        below_since=since,
        now=1000.0 + 899.0,
    )
    assert report["alert"] is False

    report, since = _evaluate_cluster_state(
        _health("yellow", unassigned=6),
        expected_configured="auto",
        alert_after_seconds=900.0,
        below_since=since,
        now=1000.0 + 901.0,
    )
    assert report["alert"] is True
    assert report["below_expected_seconds"] == 901


def test_red_alerts_immediately() -> None:
    report, since = _evaluate_cluster_state(
        _health("red", unassigned=12),
        expected_configured="auto",
        alert_after_seconds=900.0,
        below_since=None,
        now=1000.0,
    )
    assert report["below_expected"] is True
    assert report["alert"] is True
    assert since == 1000.0


def test_recovery_resets_below_since() -> None:
    _report, since = _evaluate_cluster_state(
        _health("yellow"),
        expected_configured="green",
        alert_after_seconds=900.0,
        below_since=None,
        now=1000.0,
    )
    assert since == 1000.0

    report, since = _evaluate_cluster_state(
        _health("green"),
        expected_configured="green",
        alert_after_seconds=900.0,
        below_since=since,
        now=1200.0,
    )
    assert report["below_expected"] is False
    assert since is None


def test_unreachable_cluster_counts_as_below_expected() -> None:
    report, since = _evaluate_cluster_state(
        None,
        expected_configured="green",
        alert_after_seconds=900.0,
        below_since=None,
        now=1000.0,
    )
    assert report["status"] is None
    assert report["below_expected"] is True
    assert report["alert"] is False
    assert "number_of_nodes" not in report
    assert since == 1000.0

    report, _since = _evaluate_cluster_state(
        None,
        expected_configured="green",
        alert_after_seconds=900.0,
        below_since=since,
        now=2000.0,
    )
    assert report["alert"] is True


def test_status_report_wiring(monkeypatch: pytest.MonkeyPatch) -> None:
    gauges: List[Tuple[str, float]] = []

    def fake_set_gauge(name: str, value: float, **labels: Any) -> None:
        gauges.append((name, value))

    monkeypatch.setattr(es_integration, "set_gauge", fake_set_gauge)
    monkeypatch.setattr(es_integration, "es_cluster_health", lambda: _health("green", nodes=3))
    monkeypatch.setattr(es_integration, "_below_expected_since", None)
    monkeypatch.setattr(es_integration.settings, "SEAGULL_ES_EXPECTED_STATUS", "auto", raising=False)
    monkeypatch.setattr(es_integration.settings, "SEAGULL_ES_YELLOW_ALERT_MINUTES", 15.0, raising=False)

    report = es_integration.es_cluster_status_report()

    assert report["status"] == "green"
    assert report["expected"] == "green"
    assert report["alert"] is False
    assert report["number_of_nodes"] == 3
    assert ("es_cluster_status", 0.0) in gauges
    assert ("es_cluster_below_expected", 0.0) in gauges
    assert ("es_cluster_unassigned_shards", 0.0) in gauges


def test_status_report_unreachable_sets_gauge(monkeypatch: pytest.MonkeyPatch) -> None:
    gauges: Dict[str, float] = {}

    def fake_set_gauge(name: str, value: float, **labels: Any) -> None:
        gauges[name] = value

    monkeypatch.setattr(es_integration, "set_gauge", fake_set_gauge)
    monkeypatch.setattr(es_integration, "es_cluster_health", lambda: None)
    monkeypatch.setattr(es_integration, "_below_expected_since", None)
    monkeypatch.setattr(es_integration.settings, "SEAGULL_ES_EXPECTED_STATUS", "green", raising=False)

    report: Optional[Dict[str, Any]] = es_integration.es_cluster_status_report()

    assert report is not None
    assert report["status"] is None
    assert report["below_expected"] is True
    assert gauges["es_cluster_status"] == -1.0
    assert gauges["es_cluster_below_expected"] == 1.0
    assert "es_cluster_unassigned_shards" not in gauges
