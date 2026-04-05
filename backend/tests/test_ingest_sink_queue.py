from __future__ import annotations

import time

from app.workers import ingest_worker as iw


def test_optional_sink_queue_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("NETWATCH_CLICKHOUSE_ENABLED", "true")
    monkeypatch.setenv("NETWATCH_INGEST_CLICKHOUSE_SINK_QUEUE_MAX_BATCHES", "1")
    cfg = iw.load_config()
    rt = iw._OptionalSinkRuntime(cfg=cfg, redis_client=None)

    first = rt.enqueue_clickhouse([{"event_type": "flow"}])
    second = rt.enqueue_clickhouse([{"event_type": "dns"}])

    assert first is True
    assert second is False


def test_optional_sink_enqueue_is_non_blocking_when_full(monkeypatch) -> None:
    monkeypatch.setenv("NETWATCH_CLICKHOUSE_ENABLED", "true")
    monkeypatch.setenv("NETWATCH_INGEST_CLICKHOUSE_SINK_QUEUE_MAX_BATCHES", "1")
    cfg = iw.load_config()
    rt = iw._OptionalSinkRuntime(cfg=cfg, redis_client=None)
    assert rt.enqueue_clickhouse([{"event_type": "flow"}]) is True

    started = time.perf_counter()
    ok = rt.enqueue_clickhouse([{"event_type": "flow"}])
    elapsed = time.perf_counter() - started

    assert ok is False
    assert elapsed < 0.05
