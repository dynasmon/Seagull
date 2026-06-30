from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.core.config import settings
from app.core.config.env_secrets import getenv_compat
from app.core.integrations.clickhouse import (
    clickhouse_events_table_ref,
    clickhouse_proto_intel_overview_table_ref,
    clickhouse_proto_intel_table_ref,
    ensure_clickhouse_events_schema,
    get_clickhouse_client,
    proto_intel_facet_select_sql,
    proto_intel_overview_select_sql,
)
from app.core.observability import log_event, setup_logging

setup_logging("worker-proto-intel-backfill")
logger = logging.getLogger("seagull.worker.proto_intel_backfill")


def _env_bool(name: str, default: bool) -> bool:
    raw = getenv_compat(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    raw = getenv_compat(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = getenv_compat(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except Exception:
        return default


def _env_str(name: str) -> Optional[str]:
    raw = getenv_compat(name)
    return raw.strip() if raw and raw.strip() else None


def _ch_literal(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _coerce_dt(value: object) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def main() -> int:
    settings.validate_for_service("worker-proto-intel-backfill")

    if not _env_bool("SEAGULL_PROTO_INTEL_BACKFILL_ENABLED", False):
        log_event(logger, "info", "proto_intel_backfill_disabled")
        return 0

    if not bool(getattr(settings, "SEAGULL_CLICKHOUSE_ENABLED", False)):
        log_event(logger, "info", "proto_intel_backfill_clickhouse_disabled")
        return 0

    if not ensure_clickhouse_events_schema():
        log_event(logger, "error", "proto_intel_backfill_schema_unavailable")
        return 1

    ch = get_clickhouse_client()
    raw_ref = clickhouse_events_table_ref()
    db, table = raw_ref.split(".", 1)
    facet_target = clickhouse_proto_intel_table_ref()
    overview_target = clickhouse_proto_intel_overview_table_ref()

    chunk_hours = max(1, _env_int("SEAGULL_PROTO_INTEL_BACKFILL_CHUNK_HOURS", 24))
    sleep_s = max(0.0, _env_float("SEAGULL_PROTO_INTEL_BACKFILL_SLEEP_SECONDS", 0.5))
    agent_id = _env_str("SEAGULL_PROTO_INTEL_BACKFILL_AGENT_ID")
    from_iso = _env_str("SEAGULL_PROTO_INTEL_BACKFILL_FROM")

    bounds = ch.query(f"SELECT min(timestamp), max(timestamp) FROM {raw_ref}").first_row
    min_ts = _coerce_dt(bounds[0]) if bounds else None
    if min_ts is None:
        log_event(logger, "info", "proto_intel_backfill_empty_source")
        return 0

    start = _coerce_dt(from_iso) or min_ts
    if start < min_ts:
        start = min_ts
    cutoff = datetime.now(timezone.utc)

    agent_clause = ""
    if agent_id:
        safe_agent = agent_id.replace("'", "")
        agent_clause = f" AND agent_id = '{safe_agent}'"

    chunk = timedelta(hours=chunk_hours)
    lo = start.astimezone(timezone.utc)
    processed = 0
    t0 = time.time()
    while lo < cutoff:
        hi = min(lo + chunk, cutoff)
        where = (
            f"timestamp >= toDateTime64('{_ch_literal(lo)}', 3, 'UTC') "
            f"AND timestamp < toDateTime64('{_ch_literal(hi)}', 3, 'UTC'){agent_clause}"
        )
        try:
            ch.command(f"INSERT INTO {facet_target} " + proto_intel_facet_select_sql(db=db, table=table, where=where))
            ch.command(
                f"INSERT INTO {overview_target} " + proto_intel_overview_select_sql(db=db, table=table, where=where)
            )
        except Exception as exc:
            log_event(
                logger,
                "error",
                "proto_intel_backfill_chunk_error",
                error_type=type(exc).__name__,
                window_start=_ch_literal(lo),
                window_end=_ch_literal(hi),
            )
            return 1
        processed += 1
        log_event(
            logger,
            "info",
            "proto_intel_backfill_chunk_ok",
            window_start=_ch_literal(lo),
            window_end=_ch_literal(hi),
            chunks=processed,
        )
        if sleep_s:
            time.sleep(sleep_s)
        lo = hi

    log_event(
        logger,
        "info",
        "proto_intel_backfill_done",
        chunks=processed,
        took_ms=int((time.time() - t0) * 1000),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
