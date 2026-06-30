from __future__ import annotations

import asyncio
import os
import time

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.core.cache import locks
from app.shared.analytics import prewarm, swr
from app.shared.analytics.read_model import (
    AnalyticalReadModel,
    iter_read_models,
    register_read_model,
    serve_read_model,
)


class _FakeCache:
    def __init__(self) -> None:
        self.store: dict[str, dict] = {}

    def get_json(self, key: str):
        return self.store.get(key)

    def set_json(self, key: str, payload: dict, ttl_s: int) -> None:
        self.store[key] = payload


def _install_cache(monkeypatch) -> _FakeCache:
    cache = _FakeCache()
    monkeypatch.setattr(swr, "get_json", cache.get_json)
    monkeypatch.setattr(swr, "set_json", cache.set_json)

    async def _acquire(_key, *, ttl_s):
        return "token"

    async def _release(_key, _token):
        return None

    monkeypatch.setattr(locks, "acquire_lock", _acquire)
    monkeypatch.setattr(locks, "release_lock", _release)
    return cache


def _payload(n: int = 1) -> dict:
    return {
        "generated_at": time.time(),
        "total_events": n,
        "app_protocols": [{"key": "tls", "count": n}],
        "meta": {"source": "clickhouse", "query_latency_ms": 1.0},
    }


def test_payload_etag_ignores_volatile_fields() -> None:
    a = swr.payload_etag({"total_events": 5, "generated_at": "t1", "meta": {"x": 1}}, schema_version=5)
    b = swr.payload_etag({"total_events": 5, "generated_at": "t2", "meta": {"x": 2}}, schema_version=5)
    c = swr.payload_etag({"total_events": 6, "generated_at": "t1", "meta": {"x": 1}}, schema_version=5)
    assert a == b
    assert a != c
    assert a.startswith('W/"5-')


def test_swr_fresh_hit_does_not_recompute(monkeypatch) -> None:
    _install_cache(monkeypatch)
    calls = {"n": 0}

    async def compute() -> dict:
        calls["n"] += 1
        return _payload(1)

    async def run() -> None:
        p1, e1, o1 = await swr.get_or_compute(
            feature="t", key="k", compute=compute, fresh_s=60, stale_s=300, schema_version=1
        )
        assert o1 == "miss"
        p2, e2, o2 = await swr.get_or_compute(
            feature="t", key="k", compute=compute, fresh_s=60, stale_s=300, schema_version=1
        )
        assert o2 == "fresh"
        assert e1 == e2

    asyncio.run(run())
    assert calls["n"] == 1


def test_swr_stale_serves_immediately_and_revalidates(monkeypatch) -> None:
    cache = _install_cache(monkeypatch)
    calls = {"n": 0}

    async def compute() -> dict:
        calls["n"] += 1
        return _payload(calls["n"])

    async def run() -> None:
        await swr.get_or_compute(feature="t", key="k", compute=compute, fresh_s=60, stale_s=300, schema_version=1)
        entry = cache.store["k"]
        entry["fresh_until"] = time.time() - 1.0
        payload, _etag, outcome = await swr.get_or_compute(
            feature="t", key="k", compute=compute, fresh_s=60, stale_s=300, schema_version=1
        )
        assert outcome == "stale"
        for _ in range(50):
            if calls["n"] >= 2:
                break
            await asyncio.sleep(0.02)
        assert calls["n"] == 2

    asyncio.run(run())


def test_single_flight_coalesces_concurrent_callers(monkeypatch) -> None:
    _install_cache(monkeypatch)
    calls = {"n": 0}

    async def compute() -> dict:
        calls["n"] += 1
        await asyncio.sleep(0.05)
        return _payload(7)

    async def run() -> None:
        results = await asyncio.gather(
            *[
                swr.get_or_compute(feature="t", key="k", compute=compute, fresh_s=60, stale_s=300, schema_version=1)
                for _ in range(10)
            ]
        )
        etags = {etag for _p, etag, _o in results}
        assert len(etags) == 1

    asyncio.run(run())
    assert calls["n"] == 1


def test_read_model_registry_and_serve(monkeypatch) -> None:
    _install_cache(monkeypatch)
    calls = {"n": 0}

    async def compute(params: dict) -> dict:
        calls["n"] += 1
        return _payload(int(params.get("since_minutes", 1)))

    model = AnalyticalReadModel(
        name="unit_model",
        schema_version=2,
        fresh_s=60,
        stale_s=300,
        key_builder=lambda p: f"unit:{p.get('since_minutes')}",
        compute=compute,
    )
    register_read_model(model)
    assert any(m.name == "unit_model" for m in iter_read_models())

    async def run() -> None:
        payload, etag, outcome = await serve_read_model(model, {"since_minutes": 720})
        assert outcome == "miss"
        assert payload["total_events"] == 720
        assert etag

    asyncio.run(run())
    assert calls["n"] == 1


def test_prewarm_registry_collects_specs() -> None:
    def _provider():
        return [prewarm.WarmSpec(feature="unit_feature", params={"since_minutes": 60})]

    prewarm.register_warm_set(_provider)
    try:
        specs = prewarm.iter_warm_specs()
        assert any(s.feature == "unit_feature" and s.params["since_minutes"] == 60 for s in specs)
    finally:
        prewarm._PROVIDERS.remove(_provider)
