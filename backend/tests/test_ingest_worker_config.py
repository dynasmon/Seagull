from __future__ import annotations

from app.workers import ingest_worker


def test_ingest_worker_clickhouse_defaults_enabled(monkeypatch) -> None:
    monkeypatch.delenv("SEAGULL_CLICKHOUSE_ENABLED", raising=False)
    monkeypatch.delenv("SEAGULL_CLICKHOUSE_REQUIRED", raising=False)
    cfg = ingest_worker.load_config()
    assert cfg.clickhouse_enabled is True
    assert cfg.clickhouse_required is True
    assert cfg.clickhouse_sink_queue_max_batches >= 1
    assert cfg.warm_sink_queue_max_batches >= 1


def test_ingest_worker_clickhouse_env_can_disable(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_CLICKHOUSE_ENABLED", "false")
    monkeypatch.setenv("SEAGULL_CLICKHOUSE_REQUIRED", "false")
    cfg = ingest_worker.load_config()
    assert cfg.clickhouse_enabled is False
    assert cfg.clickhouse_required is False


def test_ingest_worker_sink_queue_env(monkeypatch) -> None:
    monkeypatch.setenv("SEAGULL_INGEST_CLICKHOUSE_SINK_QUEUE_MAX_BATCHES", "7")
    monkeypatch.setenv("SEAGULL_INGEST_WARM_SINK_QUEUE_MAX_BATCHES", "9")
    monkeypatch.setenv("SEAGULL_INGEST_SINK_MAX_BATCH_RETRIES", "3")

    cfg = ingest_worker.load_config()
    assert cfg.clickhouse_sink_queue_max_batches == 7
    assert cfg.warm_sink_queue_max_batches == 9
    assert cfg.sink_max_batch_retries == 3
