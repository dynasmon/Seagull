from __future__ import annotations

from typing import Any

from app.core.config import settings


def _env_int(name: str, default: int) -> int:
    v = getattr(settings, name, None)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default


def _env_str(name: str, default: str) -> str:
    v = getattr(settings, name, None)
    if v is None:
        return default
    s = str(v).strip()
    return s if s else default


def _env_bool(name: str, default: bool) -> bool:
    v = getattr(settings, name, None)
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _safe_text(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return str(value or "")


def queue_key() -> str:
    return _env_str("SEAGULL_INGEST_QUEUE_KEY", "seagull:ingest:queue")


def processing_key() -> str:
    qk = queue_key()
    return _env_str("SEAGULL_INGEST_PROCESSING_KEY", f"{qk}:processing")


def deadletter_key() -> str:
    return f"{queue_key()}:deadletter"


def backlog_events_key() -> str:
    return _env_str("SEAGULL_INGEST_BACKLOG_EVENTS_KEY", "seagull:ingest:backlog_events")


def _eps_key(ts_s: int) -> str:
    return f"seagull:ingest:eps:{ts_s}"


def _stats_key(ts_s: int) -> str:
    return f"seagull:ingest:stats:{ts_s}"


def _flush_lock_key(ts_s: int) -> str:
    return f"seagull:ingest:flush:{ts_s}"


def storm_active_key() -> str:
    return _env_str("SEAGULL_INGEST_STORM_ACTIVE_KEY", "seagull:ingest:storm_active")


def storm_session_key() -> str:
    return _env_str("SEAGULL_INGEST_STORM_SESSION_KEY", "seagull:ingest:storm_session")


def storm_since_key() -> str:
    return _env_str("SEAGULL_INGEST_STORM_SINCE_KEY", "seagull:ingest:storm_since")


def storm_alert_id_key() -> str:
    return _env_str("SEAGULL_INGEST_STORM_ALERT_ID_KEY", "seagull:ingest:storm_alert_id")


def _events_per_msg_avg_key() -> str:
    return "seagull:ingest:events_per_msg_avg"


def _worker_eps_key(ts_s: int) -> str:
    return f"seagull:ingest:worker:eps:{ts_s}"


def _worker_msgs_key(ts_s: int) -> str:
    return f"seagull:ingest:worker:msgs:{ts_s}"


def _worker_hb_key(worker_id: str) -> str:
    return f"seagull:ingest:worker:hb:{worker_id}"


def _pressure_state_key() -> str:
    return "seagull:ingest:pressure_state"


def _quality_key(ts_s: int) -> str:
    return f"seagull:ingest:quality:{ts_s}"


def _overview_live_key(ts_s: int) -> str:
    return f"seagull:overview:live:1s:{ts_s}"


def _overview_live_dropped_key(ts_s: int) -> str:
    return f"seagull:overview:live:dropped:{ts_s}"


def _sink_counter_key(*, sink: str, metric: str, ts_s: int) -> str:
    return f"seagull:ingest:sink:{sink}:{metric}:{ts_s}"


def _sink_depth_key(*, sink: str) -> str:
    return f"seagull:ingest:sink:{sink}:queue_depth"


def _clickhouse_rows_key(ts_s: int) -> str:
    return f"seagull:ingest:clickhouse:rows:{ts_s}"


def _clickhouse_batches_key(ts_s: int) -> str:
    return f"seagull:ingest:clickhouse:batches:{ts_s}"


def _clickhouse_state_key() -> str:
    return "seagull:ingest:clickhouse:state"


def _clickhouse_error_type_key() -> str:
    return "seagull:ingest:clickhouse:error_type"
