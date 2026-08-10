from __future__ import annotations

from app.workers.ingest import config as ingest_worker
from app.workers.sinks import config as sink_worker


def test_ingest_worker_sink_targets_default_enabled(monkeypatch) -> None:
    monkeypatch.delenv("SEAGULL_CLICKHOUSE_ENABLED", raising=False)
    monkeypatch.delenv("SEAGULL_INGEST_WARM_ENABLED", raising=False)
    cfg = ingest_worker.load_config()
    assert cfg.clickhouse_enabled is True
    assert cfg.warm_enabled is True
    assert cfg.outbox_chunk_events >= 1


def test_ingest_worker_sink_targets_env_can_disable(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_CLICKHOUSE_ENABLED", "false")
    monkeypatch.setenv("SEAGULL_INGEST_WARM_ENABLED", "off")
    cfg = ingest_worker.load_config()
    assert cfg.clickhouse_enabled is False
    assert cfg.warm_enabled is False


def test_ingest_worker_outbox_chunk_env(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_INGEST_OUTBOX_CHUNK_EVENTS", "64")
    assert ingest_worker.load_config().outbox_chunk_events == 64


def test_dispatcher_config_retry_backoff_is_capped(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_SINK_RETRY_BACKOFF_SECONDS", "2")
    monkeypatch.setenv("SEAGULL_SINK_RETRY_BACKOFF_MAX_SECONDS", "10")
    cfg = sink_worker.load_dispatcher_config()
    assert cfg.retry_delay_seconds(1) == 2.0
    assert cfg.retry_delay_seconds(2) == 4.0
    assert cfg.retry_delay_seconds(3) == 8.0
    assert cfg.retry_delay_seconds(9) == 10.0


def test_reconciler_config_defaults(monkeypatch) -> None:
    monkeypatch.delenv("SEAGULL_PROJECTION_RECONCILE_ENABLED", raising=False)
    monkeypatch.setenv("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    cfg = sink_worker.load_reconciler_config()
    assert cfg.enabled is True
    assert cfg.search_index_pattern == "seagull-events-*"
    assert cfg.settle_seconds >= 30
