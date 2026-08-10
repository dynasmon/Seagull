from __future__ import annotations

from dataclasses import dataclass

from app.core.config.env_secrets import env_value, getenv_compat


def _env_str(name: str, default: str) -> str:
    return env_value(name, default) or default


def _env_int(name: str, default: int) -> int:
    raw = getenv_compat(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip(), 10)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = getenv_compat(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = getenv_compat(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


@dataclass(frozen=True)
class DispatcherConfig:
    clickhouse_enabled: bool
    warm_enabled: bool
    search_enabled: bool
    claim_batches: int
    lease_seconds: float
    max_attempts: int
    retry_backoff_seconds: float
    retry_backoff_max_seconds: float
    idle_sleep_seconds: float
    stats_interval_seconds: float
    dead_letter_retention_days: int
    clickhouse_reconnect_seconds: float
    warm_index_prefix: str
    warm_ilm_enabled: bool
    warm_ilm_policy: str
    warm_ilm_delete_after_days: int

    def retry_delay_seconds(self, attempts: int) -> float:
        exponent = max(0, int(attempts) - 1)
        delay = self.retry_backoff_seconds * (2.0**exponent)
        return min(delay, self.retry_backoff_max_seconds)


@dataclass(frozen=True)
class ReconcilerConfig:
    enabled: bool
    clickhouse_enabled: bool
    search_enabled: bool
    interval_seconds: float
    lookback_minutes: int
    settle_seconds: int
    repair_enabled: bool
    repair_max_events: int
    search_index_pattern: str


def load_dispatcher_config() -> DispatcherConfig:
    index_prefix = _env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    return DispatcherConfig(
        clickhouse_enabled=_env_bool("SEAGULL_CLICKHOUSE_ENABLED", True),
        warm_enabled=_env_bool("SEAGULL_INGEST_WARM_ENABLED", True),
        search_enabled=_env_bool("SEAGULL_SINK_SEARCH_ENABLED", True),
        claim_batches=max(1, _env_int("SEAGULL_SINK_CLAIM_BATCHES", 8)),
        lease_seconds=max(5.0, _env_float("SEAGULL_SINK_LEASE_SECONDS", 120.0)),
        max_attempts=max(1, _env_int("SEAGULL_SINK_MAX_ATTEMPTS", 8)),
        retry_backoff_seconds=max(0.1, _env_float("SEAGULL_SINK_RETRY_BACKOFF_SECONDS", 1.0)),
        retry_backoff_max_seconds=max(1.0, _env_float("SEAGULL_SINK_RETRY_BACKOFF_MAX_SECONDS", 60.0)),
        idle_sleep_seconds=max(0.05, _env_float("SEAGULL_SINK_IDLE_SLEEP_SECONDS", 0.5)),
        stats_interval_seconds=max(1.0, _env_float("SEAGULL_SINK_STATS_INTERVAL_SECONDS", 5.0)),
        dead_letter_retention_days=max(1, _env_int("SEAGULL_SINK_DEAD_LETTER_RETENTION_DAYS", 7)),
        clickhouse_reconnect_seconds=max(1.0, _env_float("SEAGULL_CLICKHOUSE_RECONNECT_SECONDS", 5.0)),
        warm_index_prefix=_env_str("SEAGULL_INGEST_WARM_INDEX_PREFIX", f"{index_prefix}-warm"),
        warm_ilm_enabled=_env_bool("SEAGULL_INGEST_WARM_ILM_ENABLED", True),
        warm_ilm_policy=_env_str("SEAGULL_INGEST_WARM_ILM_POLICY", "seagull-warm-delete-30d"),
        warm_ilm_delete_after_days=max(1, _env_int("SEAGULL_INGEST_WARM_ILM_DELETE_AFTER_DAYS", 30)),
    )


def load_reconciler_config() -> ReconcilerConfig:
    index_prefix = _env_str("SEAGULL_ES_INDEX_PREFIX", "seagull-events")
    return ReconcilerConfig(
        enabled=_env_bool("SEAGULL_PROJECTION_RECONCILE_ENABLED", True),
        clickhouse_enabled=_env_bool("SEAGULL_CLICKHOUSE_ENABLED", True),
        search_enabled=_env_bool("SEAGULL_SINK_SEARCH_ENABLED", True),
        interval_seconds=max(30.0, _env_float("SEAGULL_PROJECTION_RECONCILE_INTERVAL_SECONDS", 300.0)),
        lookback_minutes=max(5, _env_int("SEAGULL_PROJECTION_RECONCILE_LOOKBACK_MINUTES", 180)),
        settle_seconds=max(30, _env_int("SEAGULL_PROJECTION_RECONCILE_SETTLE_SECONDS", 120)),
        repair_enabled=_env_bool("SEAGULL_PROJECTION_REPAIR_ENABLED", True),
        repair_max_events=max(0, _env_int("SEAGULL_PROJECTION_REPAIR_MAX_EVENTS", 20000)),
        search_index_pattern=_env_str("SEAGULL_PROJECTION_SEARCH_INDEX_PATTERN", f"{index_prefix}-*"),
    )
