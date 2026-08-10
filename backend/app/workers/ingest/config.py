from __future__ import annotations

from dataclasses import dataclass

from app.core.config.env_secrets import env_value, getenv_compat


@dataclass(frozen=True)
class WorkerConfig:
    queue_key: str
    processing_key: str
    batch_messages: int
    idle_sleep_seconds: float
    clickhouse_enabled: bool
    warm_enabled: bool
    outbox_chunk_events: int
    es_stream_producer_enabled: bool
    es_stream_key: str
    es_stream_maxlen: int


def _env_str(name: str, default: str) -> str:
    return env_value(name, default) or default


def _env_int(name: str, default: int) -> int:
    v = getenv_compat(name)
    if v is None:
        return default
    v = v.strip()
    if not v:
        return default
    try:
        return int(v, 10)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    v = getenv_compat(name)
    if v is None:
        return default
    v = v.strip()
    if not v:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = getenv_compat(name)
    if v is None:
        return default
    s = v.strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def load_config() -> WorkerConfig:
    qk = _env_str("SEAGULL_INGEST_QUEUE_KEY", "seagull:ingest:queue")
    return WorkerConfig(
        queue_key=qk,
        processing_key=_env_str("SEAGULL_INGEST_PROCESSING_KEY", f"{qk}:processing"),
        batch_messages=max(1, _env_int("SEAGULL_INGEST_WORKER_BATCH_MESSAGES", 50)),
        idle_sleep_seconds=max(0.1, _env_float("SEAGULL_INGEST_WORKER_IDLE_SLEEP_SECONDS", 0.25)),
        clickhouse_enabled=_env_bool("SEAGULL_CLICKHOUSE_ENABLED", True),
        warm_enabled=_env_bool("SEAGULL_INGEST_WARM_ENABLED", True),
        outbox_chunk_events=max(1, _env_int("SEAGULL_INGEST_OUTBOX_CHUNK_EVENTS", 500)),
        es_stream_producer_enabled=_env_bool("SEAGULL_ES_STREAM_PRODUCER_ENABLED", False),
        es_stream_key=_env_str("SEAGULL_ES_STREAM_KEY", "seagull:events:index"),
        es_stream_maxlen=max(10000, _env_int("SEAGULL_ES_STREAM_MAXLEN", 1000000)),
    )
