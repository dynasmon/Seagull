from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

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
from app.shared.indexing.watermark import (
    clear_proto_intel_materialization_state,
    pin_proto_intel_materialization_range,
    read_proto_intel_materialization_floor,
    read_proto_intel_materialization_range,
    write_proto_intel_materialization_floor,
)

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


def _raw_min_ts(ch: Any, raw_ref: str) -> Optional[datetime]:
    row = ch.query(f"SELECT min(timestamp) FROM {raw_ref}").first_row
    return _coerce_dt(row[0]) if row else None


def _live_boundary(ch: Any, overview_target: str, *, after: datetime) -> datetime:
    row = ch.query(f"SELECT min(bucket_ts) FROM {overview_target}").first_row
    live_min = _coerce_dt(row[0]) if row else None
    if live_min is not None and live_min > after:
        return live_min
    return datetime.now(timezone.utc)


def _fill_window(
    ch: Any,
    *,
    db: str,
    table: str,
    facet_target: str,
    overview_target: str,
    start: datetime,
    boundary: datetime,
    chunk_hours: int,
    sleep_s: float,
) -> int:
    chunk = timedelta(hours=max(1, chunk_hours))
    lo = start.astimezone(timezone.utc)
    end = boundary.astimezone(timezone.utc)
    processed = 0
    while lo < end:
        hi = min(lo + chunk, end)
        where = (
            f"timestamp >= toDateTime64('{_ch_literal(lo)}', 3, 'UTC') "
            f"AND timestamp < toDateTime64('{_ch_literal(hi)}', 3, 'UTC')"
        )
        slot = f"{int(lo.timestamp())}:{int(hi.timestamp())}"
        ch.command(
            f"INSERT INTO {facet_target} " + proto_intel_facet_select_sql(db=db, table=table, where=where),
            settings={"insert_deduplication_token": f"pim:facet:{slot}"},
        )
        ch.command(
            f"INSERT INTO {overview_target} " + proto_intel_overview_select_sql(db=db, table=table, where=where),
            settings={"insert_deduplication_token": f"pim:overview:{slot}"},
        )
        processed += 1
        if sleep_s:
            time.sleep(sleep_s)
        lo = hi
    return processed


def run_materialization(ch: Any, *, force: bool = False, chunk_hours: int = 24, sleep_s: float = 0.0) -> Optional[datetime]:
    raw_ref = clickhouse_events_table_ref()
    db, table = raw_ref.split(".", 1)
    facet_target = clickhouse_proto_intel_table_ref()
    overview_target = clickhouse_proto_intel_overview_table_ref()

    if force:
        clear_proto_intel_materialization_state()
        ch.command(f"TRUNCATE TABLE IF EXISTS {facet_target}")
        ch.command(f"TRUNCATE TABLE IF EXISTS {overview_target}")

    floor = read_proto_intel_materialization_floor()
    if floor is not None and not force:
        return floor

    raw_min = _raw_min_ts(ch, raw_ref)
    if raw_min is None:
        return None
    start = raw_min.replace(second=0, microsecond=0)

    pinned = pin_proto_intel_materialization_range(
        start_ts=start,
        boundary_ts=_live_boundary(ch, overview_target, after=start),
    )
    if pinned is None:
        return None
    start, boundary = pinned

    processed = _fill_window(
        ch,
        db=db,
        table=table,
        facet_target=facet_target,
        overview_target=overview_target,
        start=start,
        boundary=boundary,
        chunk_hours=chunk_hours,
        sleep_s=sleep_s,
    )
    write_proto_intel_materialization_floor(floor_ts=start)
    log_event(
        logger,
        "info",
        "proto_intel_materialized",
        floor=start.isoformat(),
        boundary=boundary.isoformat(),
        chunks=processed,
    )
    return start


def main() -> int:
    settings.validate_for_service("worker-proto-intel-backfill")

    if not _env_bool("SEAGULL_PROTO_INTEL_BACKFILL_ENABLED", True):
        log_event(logger, "info", "proto_intel_backfill_disabled")
        return 0

    if not bool(getattr(settings, "SEAGULL_CLICKHOUSE_ENABLED", False)):
        log_event(logger, "info", "proto_intel_backfill_clickhouse_disabled")
        return 0

    if not ensure_clickhouse_events_schema():
        log_event(logger, "error", "proto_intel_backfill_schema_unavailable")
        return 1

    ch = get_clickhouse_client()
    t0 = time.time()
    try:
        floor = run_materialization(
            ch,
            force=_env_bool("SEAGULL_PROTO_INTEL_BACKFILL_FORCE", False),
            chunk_hours=max(1, _env_int("SEAGULL_PROTO_INTEL_BACKFILL_CHUNK_HOURS", 24)),
            sleep_s=max(0.0, _env_float("SEAGULL_PROTO_INTEL_BACKFILL_SLEEP_SECONDS", 0.5)),
        )
    except Exception as exc:
        log_event(logger, "error", "proto_intel_backfill_error", error_type=type(exc).__name__)
        return 1

    log_event(
        logger,
        "info",
        "proto_intel_backfill_done",
        floor=floor.isoformat() if floor else None,
        took_ms=int((time.time() - t0) * 1000),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
