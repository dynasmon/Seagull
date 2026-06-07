from __future__ import annotations

import math
import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import pytest

from app.core.config import settings as app_settings
from app.core.integrations import prometheus as prom
from app.core.integrations.prometheus import (
    InstantSample,
    PrometheusQueryError,
    PrometheusUnavailable,
    QueryResponse,
    RangeSeries,
    _envelope_to_response,
)
from app.core.observability import queries
from app.core.observability.queries import QueryValidationError


def test_parse_vector_envelope() -> None:
    data = {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [{"metric": {"__name__": "x", "severity": "high"}, "value": [1700000000.5, "3.5"]}],
        },
    }
    resp = _envelope_to_response(data)
    assert resp.result_type == "vector"
    assert len(resp.samples) == 1
    sample = resp.samples[0]
    assert sample.metric["severity"] == "high"
    assert sample.value == 3.5
    assert sample.timestamp == 1700000000.5
    assert resp.series == []


def test_parse_matrix_envelope() -> None:
    data = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [{"metric": {"worker_group": "ingest"}, "values": [[1700000000, "1"], [1700000015, "2"]]}],
        },
    }
    resp = _envelope_to_response(data)
    assert resp.result_type == "matrix"
    assert len(resp.series) == 1
    series = resp.series[0]
    assert series.metric["worker_group"] == "ingest"
    assert series.points == [(1700000000.0, 1.0), (1700000015.0, 2.0)]


def test_parse_scalar_envelope() -> None:
    data = {"status": "success", "data": {"resultType": "scalar", "result": [1700000000, "42"]}}
    resp = _envelope_to_response(data)
    assert resp.result_type == "scalar"
    assert resp.samples[0].value == 42.0


def test_error_envelope_raises_query_error() -> None:
    data = {"status": "error", "errorType": "bad_data", "error": "1:1: parse error"}
    with pytest.raises(PrometheusQueryError) as exc:
        _envelope_to_response(data)
    assert exc.value.error_type == "bad_data"


def test_nonfinite_values_parse_to_nan() -> None:
    data = {
        "status": "success",
        "data": {"resultType": "vector", "result": [{"metric": {}, "value": [1.0, "NaN"]}]},
    }
    resp = _envelope_to_response(data)
    assert math.isnan(resp.samples[0].value)


def test_catalogue_is_grounded_and_threads_window() -> None:
    assert queries.CATALOGUE
    for spec in queries.CATALOGUE.values():
        promql = spec.builder("5m")
        assert isinstance(promql, str) and promql
        if spec.requires_window:
            assert "[5m]" in promql


def test_list_query_catalogue_is_sorted_metadata() -> None:
    catalogue = queries.list_query_catalogue()
    keys = [item["key"] for item in catalogue]
    assert keys == sorted(keys)
    sample = next(item for item in catalogue if item["key"] == "http_request_rate")
    assert sample["unit"] == "ops"
    assert "instant" in sample["kinds"] and "range" in sample["kinds"]
    assert sample["requires_window"] is True


def test_unknown_query_key_rejected() -> None:
    with pytest.raises(QueryValidationError):
        queries.run_instant("does_not_exist")


def test_window_validation() -> None:
    assert queries.validate_window(None) == queries.DEFAULT_WINDOW
    assert queries.validate_window("1h") == "1h"
    with pytest.raises(QueryValidationError):
        queries.validate_window("13m")


def test_kind_enforcement(monkeypatch) -> None:
    spec = queries.QuerySpec(
        "fake_instant_only", "t", "d", "count",
        builder=lambda _w: "vector(1)", requires_window=False, allow_instant=True, allow_range=False,
    )
    monkeypatch.setitem(queries.CATALOGUE, spec.key, spec)
    with pytest.raises(QueryValidationError):
        queries.run_range(spec.key, start=0, end=60)


def test_resolve_range_derives_safe_step() -> None:
    s, e, step = queries.resolve_range(0, 3600)
    assert step >= queries.MIN_STEP_SECONDS
    assert (e - s) / step <= queries.MAX_POINTS


def test_resolve_range_rejects_reversed_and_empty() -> None:
    with pytest.raises(QueryValidationError):
        queries.resolve_range(100, 100)
    with pytest.raises(QueryValidationError):
        queries.resolve_range(200, 100)


def test_resolve_range_rejects_oversized_span() -> None:
    with pytest.raises(QueryValidationError):
        queries.resolve_range(0, queries.MAX_RANGE_SECONDS + 1)


def test_resolve_range_rejects_too_many_points() -> None:
    with pytest.raises(QueryValidationError):
        queries.resolve_range(0, 100_000, step=15)


def test_resolve_range_rejects_step_below_floor() -> None:
    with pytest.raises(QueryValidationError):
        queries.resolve_range(0, 3600, step=5)


def test_rate_window_for_step() -> None:
    assert queries.rate_window_for_step(15) == "1m"
    assert queries.rate_window_for_step(30) == "2m"
    assert queries.rate_window_for_step(10_000) == "1h"


def test_run_instant_builds_promql_and_wraps_result(monkeypatch) -> None:
    captured: dict = {}

    def fake_instant(promql: str, *, time_unix=None) -> QueryResponse:
        captured["promql"] = promql
        return QueryResponse(result_type="vector", samples=[InstantSample(metric={}, value=2.0, timestamp=1.0)])

    monkeypatch.setattr(queries.prom, "instant_query", fake_instant)

    result = queries.run_instant("http_request_rate", window="1m")
    assert captured["promql"] == "sum(rate(http_requests_total[1m]))"

    payload = result.to_dict()
    assert payload["key"] == "http_request_rate"
    assert payload["unit"] == "ops"
    assert payload["kind"] == "instant"
    assert payload["samples"][0]["value"] == 2.0


def test_run_range_bounds_and_derives_window(monkeypatch) -> None:
    captured: dict = {}

    def fake_range(promql: str, *, start: float, end: float, step: float) -> QueryResponse:
        captured.update(promql=promql, start=start, end=end, step=step)
        return QueryResponse(
            result_type="matrix",
            series=[RangeSeries(metric={"severity": "high"}, points=[(1.0, 2.0), (2.0, float("inf"))])],
        )

    monkeypatch.setattr(queries.prom, "range_query", fake_range)

    result = queries.run_range("alert_created_rate_by_severity", start=0, end=3600)
    assert captured["step"] >= queries.MIN_STEP_SECONDS
    assert captured["promql"].startswith("sum by (severity) (rate(alert_created_total[")

    payload = result.to_dict()
    assert payload["kind"] == "range"
    points = payload["series"][0]["points"]
    assert points[0] == [1.0, 2.0]
    assert points[1][1] is None


def test_to_dict_sanitizes_nan(monkeypatch) -> None:
    monkeypatch.setattr(
        queries.prom,
        "instant_query",
        lambda promql, *, time_unix=None: QueryResponse(
            result_type="vector", samples=[InstantSample(metric={}, value=float("nan"), timestamp=1.0)]
        ),
    )
    payload = queries.run_instant("http_error_ratio").to_dict()
    assert payload["samples"][0]["value"] is None


def test_disabled_prometheus_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(app_settings, "SEAGULL_PROMETHEUS_ENABLED", False)
    prom.reset_state()
    assert prom.is_available() is False
    with pytest.raises(PrometheusUnavailable):
        prom.instant_query("vector(1)")
