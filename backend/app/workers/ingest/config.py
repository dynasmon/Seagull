from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.core.config.env_secrets import env_value, getenv_compat


@dataclass(frozen=True)
class WorkerConfig:
    queue_key: str
    processing_key: str
    batch_messages: int
    idle_sleep_seconds: float
    values_page_size: int
    rollup_page_size: int
    warm_enabled: bool
    es_url: str
    es_index_prefix: str
    warm_index_prefix: str
    warm_ilm_enabled: bool
    warm_ilm_policy: str
    warm_ilm_delete_after_days: int
    es_request_timeout_seconds: int
    es_username: Optional[str]
    es_password: Optional[str]
    es_verify_certs: bool
    es_ca_certs: Optional[str]
    clickhouse_enabled: bool
    clickhouse_required: bool
    clickhouse_reconnect_seconds: float
    clickhouse_sink_queue_max_batches: int
    warm_sink_queue_max_batches: int
    sink_max_batch_retries: int


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
    except Exception:
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
    except Exception:
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
        values_page_size=max(100, _env_int("SEAGULL_INGEST_VALUES_PAGE_SIZE", 1000)),
        rollup_page_size=max(100, _env_int("SEAGULL_INGEST_ROLLUP_PAGE_SIZE", 500)),
        warm_enabled=_env_bool("SEAGULL_INGEST_WARM_ENABLED", True),
        es_url=_env_str("SEAGULL_ES_URL", "http://elasticsearch:9200"),
        es_index_prefix=_env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events"),
        warm_index_prefix=_env_str("SEAGULL_INGEST_WARM_INDEX_PREFIX", _env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events") + "-warm"),
        warm_ilm_enabled=_env_bool("SEAGULL_INGEST_WARM_ILM_ENABLED", True),
        warm_ilm_policy=_env_str("SEAGULL_INGEST_WARM_ILM_POLICY", "seagull-warm-delete-30d"),
        warm_ilm_delete_after_days=max(1, _env_int("SEAGULL_INGEST_WARM_ILM_DELETE_AFTER_DAYS", 30)),
        es_request_timeout_seconds=max(5, _env_int("SEAGULL_ES_REQUEST_TIMEOUT_SECONDS", 30)),
        es_username=env_value("SEAGULL_ES_USERNAME", None),
        es_password=env_value("SEAGULL_ES_PASSWORD", None),
        es_verify_certs=_env_bool("SEAGULL_ES_VERIFY_CERTS", True),
        es_ca_certs=env_value("SEAGULL_ES_CA_CERTS", None),
        clickhouse_enabled=_env_bool("SEAGULL_CLICKHOUSE_ENABLED", True),
        clickhouse_required=_env_bool("SEAGULL_CLICKHOUSE_REQUIRED", True),
        clickhouse_reconnect_seconds=max(1.0, _env_float("SEAGULL_CLICKHOUSE_RECONNECT_SECONDS", 5.0)),
        clickhouse_sink_queue_max_batches=max(1, _env_int("SEAGULL_INGEST_CLICKHOUSE_SINK_QUEUE_MAX_BATCHES", 128)),
        warm_sink_queue_max_batches=max(1, _env_int("SEAGULL_INGEST_WARM_SINK_QUEUE_MAX_BATCHES", 128)),
        sink_max_batch_retries=max(0, _env_int("SEAGULL_INGEST_SINK_MAX_BATCH_RETRIES", 1)),
    )
