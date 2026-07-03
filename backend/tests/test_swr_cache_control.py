from __future__ import annotations

import os

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")

from app.shared.analytics import read_model as read_model_registry
from app.shared.analytics.http_cache import (
    SWR_ROUTE_READ_MODELS,
    swr_cache_control,
    swr_cache_control_middleware,
)
from app.shared.analytics.read_model import AnalyticalReadModel


def _fake_model(name: str, *, fresh_s: int, stale_s: int) -> AnalyticalReadModel:
    async def _compute(_params: dict) -> dict:
        return {}

    return AnalyticalReadModel(
        name=name,
        schema_version=1,
        fresh_s=fresh_s,
        stale_s=stale_s,
        key_builder=lambda _params: name,
        compute=_compute,
    )


def _build_app() -> FastAPI:
    app = FastAPI()
    app.middleware("http")(swr_cache_control_middleware)

    @app.get("/cache-probe")
    async def probe() -> dict:
        return {"ok": True}

    @app.post("/cache-probe")
    async def probe_post() -> dict:
        return {"ok": True}

    @app.get("/cache-probe-explicit")
    async def probe_explicit(response: Response) -> dict:
        response.headers["Cache-Control"] = "no-store"
        return {"ok": True}

    @app.get("/cache-probe-304")
    async def probe_not_modified() -> Response:
        return Response(status_code=304)

    @app.get("/cache-probe-error")
    async def probe_error() -> Response:
        return Response(status_code=503)

    @app.get("/cache-probe-unmapped")
    async def probe_unmapped() -> dict:
        return {"ok": True}

    return app


@pytest.fixture()
def probe_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    model = _fake_model("swr_cache_probe", fresh_s=7, stale_s=77)
    monkeypatch.setitem(read_model_registry._REGISTRY, model.name, model)
    for route in ("/cache-probe", "/cache-probe-explicit", "/cache-probe-304", "/cache-probe-error"):
        monkeypatch.setitem(SWR_ROUTE_READ_MODELS, route, model.name)
    return TestClient(_build_app())


def test_swr_cache_control_requires_route_and_model() -> None:
    assert swr_cache_control(None) is None
    assert swr_cache_control("") is None
    assert swr_cache_control("/not-mapped") is None


def test_swr_cache_control_ignores_unregistered_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(SWR_ROUTE_READ_MODELS, "/ghost", "swr_cache_ghost_model")

    assert swr_cache_control("/ghost") is None


def test_swr_cache_control_resolves_fixed_overview_range(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _fake_model("overview_fixed_range", fresh_s=11, stale_s=111)
    monkeypatch.setitem(read_model_registry._REGISTRY, model.name, model)

    value = swr_cache_control(
        "/overview",
        {"start_ts": "2026-07-01T00:00:00Z", "end_ts": "2026-07-02T00:00:00Z"},
    )

    assert value == "private, max-age=11, stale-while-revalidate=111"


def test_swr_route_map_matches_registered_read_models() -> None:
    import app.features.alerts.service  # noqa: F401
    import app.features.events.service  # noqa: F401
    import app.features.exposure.service  # noqa: F401
    import app.features.network_topology.service  # noqa: F401
    import app.features.overview.service  # noqa: F401
    import app.features.vuln.overview  # noqa: F401

    for route, model_name in SWR_ROUTE_READ_MODELS.items():
        model = read_model_registry.get_read_model(model_name)
        assert model is not None, f"route {route} maps to unregistered read model {model_name}"
        expected = f"private, max-age={int(model.fresh_s)}, stale-while-revalidate={int(model.stale_s)}"
        assert swr_cache_control(route) == expected

    assert read_model_registry.get_read_model("overview_fixed_range") is not None


def test_middleware_sets_swr_cache_control_on_get(probe_client: TestClient) -> None:
    res = probe_client.get("/cache-probe")

    assert res.status_code == 200
    assert res.headers["Cache-Control"] == "private, max-age=7, stale-while-revalidate=77"


def test_middleware_repeats_header_on_304(probe_client: TestClient) -> None:
    res = probe_client.get("/cache-probe-304")

    assert res.status_code == 304
    assert res.headers["Cache-Control"] == "private, max-age=7, stale-while-revalidate=77"


def test_middleware_does_not_override_handler_header(probe_client: TestClient) -> None:
    res = probe_client.get("/cache-probe-explicit")

    assert res.status_code == 200
    assert res.headers["Cache-Control"] == "no-store"


def test_middleware_skips_non_get_methods(probe_client: TestClient) -> None:
    res = probe_client.post("/cache-probe")

    assert res.status_code == 200
    assert "Cache-Control" not in res.headers


def test_middleware_skips_unmapped_routes(probe_client: TestClient) -> None:
    res = probe_client.get("/cache-probe-unmapped")

    assert res.status_code == 200
    assert "Cache-Control" not in res.headers


def test_middleware_skips_error_responses(probe_client: TestClient) -> None:
    res = probe_client.get("/cache-probe-error")

    assert res.status_code == 503
    assert "Cache-Control" not in res.headers
