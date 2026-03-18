from __future__ import annotations

from app.workers import ingest_worker


def test_ingest_worker_clickhouse_defaults_enabled(monkeypatch) -> None:
    monkeypatch.delenv("NETWATCH_CLICKHOUSE_ENABLED", raising=False)
    monkeypatch.delenv("NETWATCH_CLICKHOUSE_REQUIRED", raising=False)
    cfg = ingest_worker.load_config()
    assert cfg.clickhouse_enabled is True
    assert cfg.clickhouse_required is True


def test_ingest_worker_clickhouse_env_can_disable(monkeypatch) -> None:
    monkeypatch.setenv("NETWATCH_CLICKHOUSE_ENABLED", "false")
    monkeypatch.setenv("NETWATCH_CLICKHOUSE_REQUIRED", "false")
    cfg = ingest_worker.load_config()
    assert cfg.clickhouse_enabled is False
    assert cfg.clickhouse_required is False
