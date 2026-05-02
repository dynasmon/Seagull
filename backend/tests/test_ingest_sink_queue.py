from __future__ import annotations

import time

from app.workers.ingest.config import load_config
from app.workers.ingest.sink_runtime import _OptionalSinkRuntime


def test_optional_sink_queue_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_CLICKHOUSE_ENABLED", "true")
    monkeypatch.setenv("SEAGULL_INGEST_CLICKHOUSE_SINK_QUEUE_MAX_BATCHES", "1")
    cfg = load_config()
    rt = _OptionalSinkRuntime(cfg=cfg, redis_client=None)

    first = rt.enqueue_clickhouse([{"event_type": "flow"}])
    second = rt.enqueue_clickhouse([{"event_type": "dns"}])

    assert first is True
    assert second is False


def test_optional_sink_enqueue_is_non_blocking_when_full(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_CLICKHOUSE_ENABLED", "true")
    monkeypatch.setenv("SEAGULL_INGEST_CLICKHOUSE_SINK_QUEUE_MAX_BATCHES", "1")
    cfg = load_config()
    rt = _OptionalSinkRuntime(cfg=cfg, redis_client=None)
    assert rt.enqueue_clickhouse([{"event_type": "flow"}]) is True

    started = time.perf_counter()
    ok = rt.enqueue_clickhouse([{"event_type": "flow"}])
    elapsed = time.perf_counter() - started

    assert ok is False
    assert elapsed < 0.05
