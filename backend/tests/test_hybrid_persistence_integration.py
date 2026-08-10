from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

from app.core.config import settings
from app.core.db import engine
from app.core.integrations.clickhouse import (
    clickhouse_events_table_ref,
    clickhouse_is_available,
    clickhouse_is_enabled,
    ensure_clickhouse_events_schema,
    get_clickhouse_client,
    reset_clickhouse_client,
)
from app.features.auth.session import PortalPrincipal, get_current_user
from app.features.events.worker_runtime import write_clickhouse_events
from app.main import app
from app.shared.outbox import store
from app.shared.outbox.models import SINK_CLICKHOUSE
from app.workers.ingest.hot_store import _insert_hot_rows_with_pg_ids
from app.workers.sinks.clickhouse import ClickHouseDelivery
from app.workers.sinks.config import load_dispatcher_config
from app.workers.sinks.dispatcher import OutboxDispatcher


def _flag_enabled(name: str) -> bool:
    return (os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"})


def _mk_hot_row(agent_id: str, *, event_type: str = "dns", extra: dict | None = None) -> dict:
    return {
        "agent_id": agent_id,
        "event_type": event_type,
        "schema_version": 1,
        "timestamp": datetime.now(timezone.utc),
        "src_ip": "10.0.0.10",
        "dst_ip": "8.8.8.8",
        "src_port": 56000,
        "dst_port": 53,
        "proto": "udp",
        "bytes": 123,
        "extra": dict(extra or {"app_proto": "dns", "dns_qname": "integration.example", "severity": "low"}),
    }


@pytest.fixture(scope="module", autouse=True)
def _integration_guard():
    if not _flag_enabled("SEAGULL_RUN_HYBRID_INTEGRATION"):
        pytest.skip("Set SEAGULL_RUN_HYBRID_INTEGRATION=true to run hybrid integration tests.")

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"Postgres unavailable for integration tests: {type(exc).__name__}")

    if not clickhouse_is_enabled():
        pytest.skip("ClickHouse integration tests require SEAGULL_CLICKHOUSE_ENABLED=true.")

    if not clickhouse_is_available():
        pytest.skip("ClickHouse unavailable for integration tests.")

    if not ensure_clickhouse_events_schema():
        pytest.skip("ClickHouse events schema unavailable for integration tests.")


@pytest.fixture
def api_client():
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=1, username="itest", role="admin")
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_insert_hot_rows_savepoint_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    agent = f"it-hybrid-sp-{uuid.uuid4().hex[:8]}"
    hot_rows = [_mk_hot_row(agent), _mk_hot_row(agent, event_type="flow")]

    with engine.begin() as conn:
        original_execute = type(conn).execute
        failed_once = {"v": False}

        def flaky_execute(self, statement, *args, **kwargs):
            params = args[0] if args else kwargs.get("parameters")
            is_bulk = isinstance(params, list) and len(params) > 1
            has_returning = bool(getattr(statement, "_returning", None))
            if not failed_once["v"] and has_returning and is_bulk:
                failed_once["v"] = True
                raise RuntimeError("simulated bulk returning failure")
            return original_execute(self, statement, *args, **kwargs)

        monkeypatch.setattr(type(conn), "execute", flaky_execute)
        inserted = _insert_hot_rows_with_pg_ids(conn, hot_rows)

    assert failed_once["v"] is True
    assert len(inserted) == len(hot_rows)
    assert all(int(r["pg_event_id"]) > 0 for r in inserted)


def test_dual_write_pg_and_clickhouse_available() -> None:
    agent = f"it-hybrid-dual-{uuid.uuid4().hex[:8]}"
    hot_row = _mk_hot_row(agent)

    with engine.begin() as conn:
        inserted = _insert_hot_rows_with_pg_ids(conn, [hot_row])

    assert len(inserted) == 1
    pg_event_id = int(inserted[0]["pg_event_id"])
    assert pg_event_id > 0

    ch = get_clickhouse_client()
    write_clickhouse_events(ch_client=ch, hot_rows=inserted)

    with engine.connect() as conn:
        pg_count = int(conn.execute(text("SELECT count(*) FROM net_events WHERE id = :id"), {"id": pg_event_id}).scalar_one())
    assert pg_count == 1

    table = clickhouse_events_table_ref()
    ch_row = ch.query(
        f"SELECT count() FROM {table} WHERE pg_event_id = {{eid:UInt64}}",
        parameters={"eid": pg_event_id},
    ).first_row
    assert int(ch_row[0]) >= 1


def test_pg_insert_when_clickhouse_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "SEAGULL_CLICKHOUSE_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "SEAGULL_CLICKHOUSE_HOST", "127.0.0.1", raising=False)
    monkeypatch.setattr(settings, "SEAGULL_CLICKHOUSE_PORT", 1, raising=False)
    monkeypatch.setattr(settings, "SEAGULL_CLICKHOUSE_CONNECT_TIMEOUT_SECONDS", 0.2, raising=False)
    monkeypatch.setattr(settings, "SEAGULL_CLICKHOUSE_SEND_RECEIVE_TIMEOUT_SECONDS", 0.2, raising=False)
    reset_clickhouse_client()

    assert ClickHouseDelivery(load_dispatcher_config())._connect() is None

    agent = f"it-hybrid-noch-{uuid.uuid4().hex[:8]}"
    with engine.begin() as conn:
        inserted = _insert_hot_rows_with_pg_ids(conn, [_mk_hot_row(agent)])

    assert len(inserted) == 1
    assert int(inserted[0]["pg_event_id"]) > 0


def test_events_recent_ch_first_deduplicates(api_client: TestClient) -> None:
    ch = get_clickhouse_client()
    agent = f"it-hybrid-recent-{uuid.uuid4().hex[:8]}"
    synthetic_pg_event_id = int(9_000_000_000 + int(uuid.uuid4().hex[:6], 16))
    base = _mk_hot_row(agent)
    base["pg_event_id"] = synthetic_pg_event_id

    write_clickhouse_events(ch_client=ch, hot_rows=[base, base])

    r = api_client.get("/events/recent", params={"limit": 20, "agent_id": agent})
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert int(data[0]["id"]) == synthetic_pg_event_id


def test_network_summary_falls_back_when_clickhouse_window_empty(api_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = f"it-hybrid-summary-{uuid.uuid4().hex[:8]}"
    row = _mk_hot_row(agent, extra={"app_proto": "dns", "dns_qname": "fallback.example", "severity": "medium"})
    with engine.begin() as conn:
        _insert_hot_rows_with_pg_ids(conn, [row])

    monkeypatch.setattr(settings, "SEAGULL_SEARCH_BACKEND", "postgres", raising=False)
    r = api_client.get("/events/network/summary", params={"since_minutes": 120, "limit": 20, "agent_id": agent})
    assert r.status_code == 200
    data = r.json()
    assert int(data["total_events"]) >= 1
    assert int(data["dns_events"]) >= 1


def test_outbox_delivers_events_to_clickhouse_exactly_once() -> None:
    ch = get_clickhouse_client()
    agent = f"it-hybrid-outbox-{uuid.uuid4().hex[:8]}"
    row = _mk_hot_row(agent, event_type="flow", extra={"severity": "high"})

    with engine.begin() as conn:
        inserted = _insert_hot_rows_with_pg_ids(conn, [row])
        store.enqueue(conn, sink=SINK_CLICKHOUSE, events=inserted, chunk_size=100)
    pg_event_id = int(inserted[0]["pg_event_id"])

    cfg = load_dispatcher_config()
    dispatcher = OutboxDispatcher(delivery=ClickHouseDelivery(cfg), cfg=cfg)
    assert dispatcher.drain_once() >= 1

    with engine.begin() as conn:
        assert store.depth(conn, sink=SINK_CLICKHOUSE).events == 0

    table = clickhouse_events_table_ref()
    ch_row = ch.query(
        f"SELECT count() FROM {table} WHERE pg_event_id = {{eid:UInt64}}",
        parameters={"eid": pg_event_id},
    ).first_row
    assert int(ch_row[0]) >= 1


def test_replayed_outbox_batch_is_deduplicated_by_clickhouse() -> None:
    ch = get_clickhouse_client()
    agent = f"it-hybrid-replay-{uuid.uuid4().hex[:8]}"

    with engine.begin() as conn:
        inserted = _insert_hot_rows_with_pg_ids(conn, [_mk_hot_row(agent, event_type="flow")])
    pg_event_id = int(inserted[0]["pg_event_id"])

    cfg = load_dispatcher_config()
    delivery = ClickHouseDelivery(cfg)
    for _ in range(3):
        assert delivery.deliver(inserted, batch_id=pg_event_id).delivered == 1

    table = clickhouse_events_table_ref()
    ch_row = ch.query(
        f"SELECT count() FROM {table} WHERE pg_event_id = {{eid:UInt64}}",
        parameters={"eid": pg_event_id},
    ).first_row
    assert int(ch_row[0]) == 1
