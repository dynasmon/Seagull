from __future__ import annotations

import os

from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://u:p@localhost:5432/seagull")

import pytest

from app.core.integrations import prometheus as prom
from app.core.integrations.prometheus import InstantSample, QueryResponse, RangeSeries
from app.core.observability.queries import QueryResult, QueryValidationError
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.observability import service
from app.main import app


def _instant_result(key: str = "http_request_rate") -> QueryResult:
    return QueryResult(
        key=key,
        title="t",
        unit="ops",
        kind="instant",
        response=QueryResponse(result_type="vector", samples=[InstantSample(metric={}, value=1.5, timestamp=2.0)]),
    )


def _override_admin() -> None:
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="admin", role="admin")


def _clear_overrides() -> None:
    app.dependency_overrides.pop(require_admin, None)


def test_status_reports_enabled_and_available(monkeypatch) -> None:
    monkeypatch.setattr(service.prom, "prometheus_is_enabled", lambda: True)
    monkeypatch.setattr(service.prom, "is_available", lambda: True)
    assert service.observability_status() == {"enabled": True, "available": True}


def test_catalogue_passthrough() -> None:
    keys = [q["key"] for q in service.query_catalogue()["queries"]]
    assert "http_request_rate" in keys
    assert keys == sorted(keys)


def test_run_instant_success_envelope(monkeypatch) -> None:
    service.reset_cache()
    monkeypatch.setattr(service.queries, "run_instant", lambda key, *, window=None: _instant_result(key))
    out = service.run_instant("http_request_rate", window="5m")
    assert out["available"] is True
    assert out["error"] is None
    assert out["result"]["samples"][0]["value"] == 1.5


def test_run_instant_unavailable_is_graceful_and_uncached(monkeypatch) -> None:
    service.reset_cache()
    calls = {"n": 0}

    def boom(key, *, window=None):
        calls["n"] += 1
        raise prom.PrometheusUnavailable("down")

    monkeypatch.setattr(service.queries, "run_instant", boom)
    out1 = service.run_instant("http_request_rate", window=None)
    service.run_instant("http_request_rate", window=None)
    assert out1 == {"available": False, "result": None, "error": "down"}
    assert calls["n"] == 2


def test_run_instant_query_error_marks_available(monkeypatch) -> None:
    service.reset_cache()

    def boom(key, *, window=None):
        raise prom.PrometheusQueryError("bad", error_type="bad_data")

    monkeypatch.setattr(service.queries, "run_instant", boom)
    out = service.run_instant("http_request_rate", window=None)
    assert out["available"] is True
    assert out["result"] is None
    assert out["error"] == "bad"


def test_run_instant_caches_success(monkeypatch) -> None:
    service.reset_cache()
    monkeypatch.setattr(service, "_cache_ttl", lambda: 30.0)
    calls = {"n": 0}

    def once(key, *, window=None):
        calls["n"] += 1
        return _instant_result(key)

    monkeypatch.setattr(service.queries, "run_instant", once)
    first = service.run_instant("http_request_rate", window="5m")
    second = service.run_instant("http_request_rate", window="5m")
    assert calls["n"] == 1
    assert first == second


def test_run_instant_validation_propagates() -> None:
    service.reset_cache()
    with pytest.raises(QueryValidationError):
        service.run_instant("nope_not_a_key", window=None)


def test_route_status_ok(monkeypatch) -> None:
    monkeypatch.setattr(service.prom, "prometheus_is_enabled", lambda: True)
    monkeypatch.setattr(service.prom, "is_available", lambda: False)
    _override_admin()
    try:
        with TestClient(app) as client:
            r = client.get("/observability/status")
        assert r.status_code == 200
        assert r.json() == {"enabled": True, "available": False}
    finally:
        _clear_overrides()


def test_route_catalogue_ok() -> None:
    _override_admin()
    try:
        with TestClient(app) as client:
            r = client.get("/observability/catalogue")
        assert r.status_code == 200
        assert "http_request_rate" in [q["key"] for q in r.json()["queries"]]
    finally:
        _clear_overrides()


def test_route_instant_query_ok(monkeypatch) -> None:
    service.reset_cache()
    monkeypatch.setattr(
        prom,
        "instant_query",
        lambda promql, *, time_unix=None: QueryResponse(
            result_type="vector", samples=[InstantSample(metric={}, value=3.0, timestamp=9.0)]
        ),
    )
    _override_admin()
    try:
        with TestClient(app) as client:
            r = client.get("/observability/query/http_request_rate?window=5m")
        assert r.status_code == 200
        body = r.json()
        assert body["available"] is True
        assert body["result"]["samples"][0]["value"] == 3.0
    finally:
        _clear_overrides()


def test_route_unknown_query_returns_400() -> None:
    _override_admin()
    try:
        with TestClient(app) as client:
            r = client.get("/observability/query/not_a_real_key")
        assert r.status_code == 400
    finally:
        _clear_overrides()


def test_route_range_defaults_ok(monkeypatch) -> None:
    service.reset_cache()
    captured: dict = {}

    def fake_range(promql, *, start, end, step):
        captured.update(start=start, end=end, step=step)
        return QueryResponse(
            result_type="matrix", series=[RangeSeries(metric={"severity": "high"}, points=[(1.0, 2.0)])]
        )

    monkeypatch.setattr(prom, "range_query", fake_range)
    _override_admin()
    try:
        with TestClient(app) as client:
            r = client.get("/observability/query/alert_created_rate_by_severity/range")
        assert r.status_code == 200
        body = r.json()
        assert body["available"] is True
        assert body["result"]["series"][0]["metric"]["severity"] == "high"
        assert captured["end"] > captured["start"]
    finally:
        _clear_overrides()


def test_route_requires_auth() -> None:
    _clear_overrides()
    with TestClient(app) as client:
        r = client.get("/observability/catalogue")
    assert r.status_code in (401, 403)
