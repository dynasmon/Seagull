from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from fastapi.testclient import TestClient

from app.core.health import report as health_report
from app.features.auth.session import PortalPrincipal, require_admin
from app.main import app

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_EDGE_CONFIGS = (
    os.path.join(_REPO_ROOT, "infra", "caddy", "Caddyfile"),
    os.path.join(_REPO_ROOT, "infra", "caddy", "Caddyfile.dev"),
    os.path.join(_REPO_ROOT, "frontend", "nginx", "default.conf"),
)

_FULL_REPORT = {
    "status": "ok",
    "ready": True,
    "service": "backend-api",
    "environment": "prod",
    "components": {
        "database": {"status": "ok", "latency_ms": 1.0, "error": None},
        "redis": {"status": "ok", "latency_ms": 0.5, "error": None},
        "elasticsearch": {"status": "ok", "cluster": {"status": "green"}},
        "redpanda": {"status": "ok", "brokers": ["redpanda:9092"]},
    },
}


def _as_admin():
    app.dependency_overrides[require_admin] = lambda: PortalPrincipal(id=1, username="root", role="admin")
    return lambda: app.dependency_overrides.pop(require_admin, None)


def test_readiness_answers_without_authentication_and_reveals_nothing(monkeypatch) -> None:
    monkeypatch.setattr(health_report, "diagnostics_report", lambda: dict(_FULL_REPORT))
    health_report.reset_readiness_cache()

    with TestClient(app) as client:
        r = client.get("/health/ready")

    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readiness_reports_degraded_with_service_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(health_report, "diagnostics_report", lambda: {**_FULL_REPORT, "ready": False})
    health_report.reset_readiness_cache()

    with TestClient(app) as client:
        r = client.get("/health/ready")

    assert r.status_code == 503
    assert r.json() == {"status": "degraded"}


def test_readiness_probes_the_stores_once_per_cache_window(monkeypatch) -> None:
    calls = {"n": 0}

    def _counted() -> dict:
        calls["n"] += 1
        return dict(_FULL_REPORT)

    monkeypatch.setattr(health_report, "diagnostics_report", _counted)
    monkeypatch.setattr(health_report.settings, "SEAGULL_HEALTH_READY_CACHE_SECONDS", 60.0, raising=False)
    health_report.reset_readiness_cache()

    with TestClient(app) as client:
        for _ in range(5):
            assert client.get("/health/ready").status_code == 200

    assert calls["n"] == 1


def test_readiness_reprobes_when_the_cache_is_disabled(monkeypatch) -> None:
    calls = {"n": 0}

    def _counted() -> dict:
        calls["n"] += 1
        return dict(_FULL_REPORT)

    monkeypatch.setattr(health_report, "diagnostics_report", _counted)
    monkeypatch.setattr(health_report.settings, "SEAGULL_HEALTH_READY_CACHE_SECONDS", 0.0, raising=False)
    health_report.reset_readiness_cache()

    with TestClient(app) as client:
        for _ in range(3):
            assert client.get("/health/ready").status_code == 200

    assert calls["n"] == 3


def test_diagnostics_requires_an_administrator() -> None:
    with TestClient(app) as client:
        r = client.get("/health/diagnostics")
    assert r.status_code == 401


def test_diagnostics_returns_the_full_component_report(monkeypatch) -> None:
    monkeypatch.setattr("app.main.diagnostics_report", lambda: dict(_FULL_REPORT))
    restore = _as_admin()
    try:
        with TestClient(app) as client:
            r = client.get("/health/diagnostics")
    finally:
        restore()

    assert r.status_code == 200
    body = r.json()
    assert body["environment"] == "prod"
    assert set(body["components"]) == {"database", "redis", "elasticsearch", "redpanda"}


def test_metrics_snapshot_requires_an_administrator() -> None:
    with TestClient(app) as client:
        r = client.get("/admin/metrics-snapshot")
    assert r.status_code == 401


def test_metrics_snapshot_returns_counters_for_an_administrator() -> None:
    restore = _as_admin()
    try:
        with TestClient(app) as client:
            r = client.get("/admin/metrics-snapshot")
    finally:
        restore()

    assert r.status_code == 200
    body = r.json()
    assert body["service"]
    assert isinstance(body["counters"], list)
    assert isinstance(body["histograms"], list)


def test_every_edge_denies_the_internal_endpoints() -> None:
    for path in _EDGE_CONFIGS:
        with open(path, encoding="utf-8") as handle:
            config = handle.read()
        assert "/api/metrics" in config, path
        assert "/api/health/diagnostics" in config, path
        assert "404" in config, path
