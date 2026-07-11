from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.shared.analytics import snapshot_store, snapshots
from app.shared.analytics.snapshot_store import SnapshotRow
from app.shared.analytics.snapshots import SnapshotPage, canonical_scope_params, collect_scopes

_FLAG = "SEAGULL_SNAPSHOT_UNIT_ENABLED"


class _FakeRedis:
    def __init__(self, members: list[str] | None = None) -> None:
        self.members = members or []
        self.zadds: list[tuple[str, dict]] = []

    def zadd(self, key: str, mapping: dict) -> None:
        self.zadds.append((key, mapping))

    def zremrangebyrank(self, key: str, start: int, stop: int) -> None:
        return None

    def expire(self, key: str, ttl: int) -> None:
        return None

    def zrevrangebyscore(self, key: str, max_s, min_s, start: int = 0, num: int | None = None):
        return self.members


def _page(
    monkeypatch,
    *,
    calls: dict,
    snapshotable=None,
    track_params=None,
    static_scopes=None,
    freshness_probe=None,
) -> SnapshotPage:
    monkeypatch.setattr(settings, _FLAG, True, raising=False)
    monkeypatch.setattr(snapshots, "get_redis", lambda: None)

    async def raw_compute(params: dict) -> dict:
        calls["n"] += 1
        return {"value": int(params.get("value") or 0), "meta": {"source": "compute"}}

    kwargs = {}
    if snapshotable is not None:
        kwargs["snapshotable"] = snapshotable
    if track_params is not None:
        kwargs["track_params"] = track_params
    if freshness_probe is not None:
        kwargs["freshness_probe"] = freshness_probe
    return SnapshotPage(
        page="unit_page",
        flag_env=_FLAG,
        schema_version=3,
        raw_compute=raw_compute,
        scope_key_builder=lambda p: f"unit:{p.get('value')}",
        static_scopes=static_scopes or (lambda: [{"value": 1}]),
        **kwargs,
    )


def _row(*, age_s: float = 0.0, schema_version: int = 3, payload: dict | None = None) -> SnapshotRow:
    return SnapshotRow(
        page="unit_page",
        scope_key="unit:1",
        schema_version=schema_version,
        payload=payload or {"value": 42, "meta": {"source": "compute"}},
        computed_at=datetime.now(timezone.utc) - timedelta(seconds=age_s),
        computed_ms=12.5,
    )


def test_flag_off_bypasses_store(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)
    monkeypatch.setattr(settings, _FLAG, False, raising=False)

    def _boom(*args, **kwargs):
        raise AssertionError("store must not be consulted when the flag is off")

    monkeypatch.setattr(snapshot_store, "read_snapshot", _boom)
    payload = asyncio.run(page.compute({"value": 1}))
    assert payload["value"] == 1
    assert calls["n"] == 1


def test_not_snapshotable_bypasses_store(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls, snapshotable=lambda p: False)

    def _boom(*args, **kwargs):
        raise AssertionError("store must not be consulted for non-snapshotable params")

    monkeypatch.setattr(snapshot_store, "read_snapshot", _boom)
    payload = asyncio.run(page.compute({"value": 1}))
    assert payload["value"] == 1
    assert calls["n"] == 1


def test_fresh_snapshot_served_without_recompute(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda page_name, scope_key: _row(age_s=1.0))

    payload = asyncio.run(page.compute({"value": 1}))
    assert payload["value"] == 42
    assert calls["n"] == 0
    snap_meta = payload["meta"]["snapshot"]
    assert snap_meta["computed_ms"] == 12.5
    assert snap_meta["degraded"] is False
    assert snap_meta["age_s"] >= 0.0


def test_degraded_snapshot_is_still_served(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)
    monkeypatch.setattr(settings, "SEAGULL_SNAPSHOTS_EVERY_SECONDS", 30.0, raising=False)
    monkeypatch.setattr(settings, "SEAGULL_SNAPSHOTS_MAX_AGE_MULTIPLIER", 6.0, raising=False)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda page_name, scope_key: _row(age_s=90.0))

    payload = asyncio.run(page.compute({"value": 1}))
    assert payload["value"] == 42
    assert calls["n"] == 0
    assert payload["meta"]["snapshot"]["degraded"] is True


def test_missing_snapshot_falls_back_to_compute(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda page_name, scope_key: None)

    payload = asyncio.run(page.compute({"value": 7}))
    assert payload["value"] == 7
    assert calls["n"] == 1


def test_stale_snapshot_falls_back_to_compute(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)
    monkeypatch.setattr(settings, "SEAGULL_SNAPSHOTS_EVERY_SECONDS", 30.0, raising=False)
    monkeypatch.setattr(settings, "SEAGULL_SNAPSHOTS_MAX_AGE_MULTIPLIER", 6.0, raising=False)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda page_name, scope_key: _row(age_s=500.0))

    payload = asyncio.run(page.compute({"value": 7}))
    assert payload["value"] == 7
    assert calls["n"] == 1


def test_outdated_snapshot_falls_back_to_compute(monkeypatch) -> None:
    calls = {"n": 0}
    probes: list[tuple[dict, dict]] = []

    def _probe(payload: dict, params: dict) -> bool:
        probes.append((payload, params))
        return True

    page = _page(monkeypatch, calls=calls, freshness_probe=_probe)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda page_name, scope_key: _row(age_s=1.0))

    payload = asyncio.run(page.compute({"value": 7}))
    assert payload["value"] == 7
    assert calls["n"] == 1
    assert probes and probes[0][0]["value"] == 42
    assert probes[0][1] == {"value": 7}


def test_freshness_probe_error_still_serves_snapshot(monkeypatch) -> None:
    calls = {"n": 0}

    def _probe(payload: dict, params: dict) -> bool:
        raise RuntimeError("redis down")

    page = _page(monkeypatch, calls=calls, freshness_probe=_probe)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda page_name, scope_key: _row(age_s=1.0))

    payload = asyncio.run(page.compute({"value": 1}))
    assert payload["value"] == 42
    assert calls["n"] == 0


def test_schema_mismatch_falls_back_to_compute(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)
    monkeypatch.setattr(
        snapshot_store, "read_snapshot", lambda page_name, scope_key: _row(schema_version=2)
    )

    payload = asyncio.run(page.compute({"value": 7}))
    assert payload["value"] == 7
    assert calls["n"] == 1


def test_store_read_error_falls_back_to_compute(monkeypatch) -> None:
    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)

    def _explode(page_name: str, scope_key: str):
        raise RuntimeError("db down")

    monkeypatch.setattr(snapshot_store, "read_snapshot", _explode)
    payload = asyncio.run(page.compute({"value": 7}))
    assert payload["value"] == 7
    assert calls["n"] == 1


def test_consulted_scope_is_recorded_for_dynamic_registry(monkeypatch) -> None:
    calls = {"n": 0}
    fake = _FakeRedis()
    page = _page(
        monkeypatch,
        calls=calls,
        track_params=lambda p: {"value": int(p["value"])},
    )
    monkeypatch.setattr(snapshots, "get_redis", lambda: fake)
    monkeypatch.setattr(snapshot_store, "read_snapshot", lambda page_name, scope_key: None)

    asyncio.run(page.compute({"value": 9}))
    assert len(fake.zadds) == 1
    key, mapping = fake.zadds[0]
    assert key.endswith("unit_page")
    assert canonical_scope_params({"value": 9}) in mapping


def test_collect_scopes_merges_and_dedups_static_and_dynamic(monkeypatch) -> None:
    calls = {"n": 0}
    members = [
        canonical_scope_params({"value": 1}),
        canonical_scope_params({"value": 2}),
        "not-json{",
    ]
    page = _page(
        monkeypatch,
        calls=calls,
        track_params=lambda p: p,
        static_scopes=lambda: [{"value": 1}],
    )
    monkeypatch.setattr(snapshots, "get_redis", lambda: _FakeRedis(members))

    scopes = collect_scopes(page)
    keys = [page.scope_key(p) for p in scopes]
    assert keys == ["unit:1", "unit:2"]


def test_worker_materializes_scope_and_handler_serves_it(monkeypatch) -> None:
    from app.workers.analytics import snapshots as _pkg  # noqa: F401
    from app.workers.analytics.snapshots import main as worker_main

    calls = {"n": 0}
    page = _page(monkeypatch, calls=calls)
    stored: dict[tuple[str, str], SnapshotRow] = {}

    def _fake_upsert(
        *,
        page: str,
        scope_key: str,
        schema_version: int,
        payload: dict,
        computed_ms: float,
        computed_at: datetime | None = None,
    ) -> None:
        stored[(page, scope_key)] = SnapshotRow(
            page=page,
            scope_key=scope_key,
            schema_version=schema_version,
            payload=payload,
            computed_at=computed_at or datetime.now(timezone.utc),
            computed_ms=computed_ms,
        )

    def _fake_read(page_name: str, scope_key: str) -> SnapshotRow | None:
        return stored.get((page_name, scope_key))

    monkeypatch.setattr(snapshot_store, "upsert_snapshot", _fake_upsert)
    monkeypatch.setattr(snapshot_store, "read_snapshot", _fake_read)
    monkeypatch.setattr(worker_main, "get_redis", lambda: None)

    async def _acquire(_key: str, *, ttl_s: float):
        return "token"

    async def _release(_key: str, _token: str) -> None:
        return None

    monkeypatch.setattr(worker_main, "acquire_lock", _acquire)
    monkeypatch.setattr(worker_main, "release_lock", _release)

    stats = asyncio.run(worker_main.run_page(page))
    assert stats == {"ok": 1, "error": 0, "locked": 0}
    assert ("unit_page", "unit:1") in stored
    assert calls["n"] == 1

    payload = asyncio.run(page.compute({"value": 1}))
    assert calls["n"] == 1
    assert payload["value"] == 1
    assert "snapshot" in payload["meta"]


def test_worker_page_error_does_not_abort_other_scopes(monkeypatch) -> None:
    from app.workers.analytics.snapshots import main as worker_main

    monkeypatch.setattr(settings, _FLAG, True, raising=False)
    monkeypatch.setattr(snapshots, "get_redis", lambda: None)
    monkeypatch.setattr(worker_main, "get_redis", lambda: None)

    async def _acquire(_key: str, *, ttl_s: float):
        return "token"

    async def _release(_key: str, _token: str) -> None:
        return None

    monkeypatch.setattr(worker_main, "acquire_lock", _acquire)
    monkeypatch.setattr(worker_main, "release_lock", _release)

    written: list[str] = []

    def _fake_upsert(**kwargs) -> None:
        written.append(kwargs["scope_key"])

    monkeypatch.setattr(snapshot_store, "upsert_snapshot", _fake_upsert)

    async def raw_compute(params: dict) -> dict:
        if params["value"] == 1:
            raise RuntimeError("boom")
        return {"value": params["value"]}

    page = SnapshotPage(
        page="unit_page",
        flag_env=_FLAG,
        schema_version=1,
        raw_compute=raw_compute,
        scope_key_builder=lambda p: f"unit:{p.get('value')}",
        static_scopes=lambda: [{"value": 1}, {"value": 2}],
    )

    stats = asyncio.run(worker_main.run_page(page))
    assert stats["error"] == 1
    assert stats["ok"] == 1
    assert written == ["unit:2"]


def test_overview_snapshot_scope_contract(monkeypatch) -> None:
    from app.features.overview import service as overview_service

    params = {
        "window_minutes": 60,
        "start_ts": None,
        "end_ts": None,
        "agent_id": "agent-1",
        "lite": False,
        "fixed_range": False,
    }
    tracked = overview_service._overview_track_params(params)
    assert tracked == {"window_minutes": 60, "agent_id": "agent-1", "lite": False}
    assert overview_service._overview_cache_key(tracked) == overview_service._overview_cache_key(params)

    fixed = dict(params, fixed_range=True, start_ts=datetime.now(timezone.utc))
    assert overview_service._overview_track_params(fixed) is None

    off_preset = dict(params, window_minutes=61)
    assert overview_service._overview_track_params(off_preset) is None

    scopes = overview_service._overview_snapshot_scopes()
    assert {"window_minutes": 60, "agent_id": None, "lite": False} in scopes
    assert any(scope["lite"] for scope in scopes)
    labels = {overview_service._overview_scope_label(scope) for scope in scopes}
    assert "w60:global" in labels
    assert "w60:global:lite" in labels


def test_snapshot_pages_registered_for_all_flagged_pages() -> None:
    from app.features.exposure import service as _exposure_service  # noqa: F401
    from app.features.network_topology import service as _topology_service  # noqa: F401
    from app.features.overview import service as _overview_service  # noqa: F401
    from app.features.vuln import overview as _vuln_overview  # noqa: F401

    registered = {p.page for p in snapshots.iter_snapshot_pages()}
    expected = {
        "overview",
        "exposure_summary",
        "network_topology_summary",
        "vuln_summary",
        "vuln_posture",
    }
    assert expected.issubset(registered)


def test_canonical_scope_params_is_stable() -> None:
    a = canonical_scope_params({"b": 1, "a": None})
    b = canonical_scope_params({"a": None, "b": 1})
    assert a == b
    assert time.time() > 0
