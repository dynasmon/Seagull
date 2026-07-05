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
    get_clickhouse_long_ops_client,
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


def _settings_chunk_hours(override: Optional[int]) -> int:
    if override:
        return max(1, int(override))
    return max(1, int(getattr(settings, "SEAGULL_PROTO_INTEL_BACKFILL_CHUNK_HOURS", 6) or 6))


def _settings_sleep_s(override: Optional[float]) -> float:
    if override is not None:
        return max(0.0, float(override))
    return max(0.0, float(getattr(settings, "SEAGULL_PROTO_INTEL_BACKFILL_SLEEP_SECONDS", 0.5) or 0.0))


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
    # minOrNull: plain min() over an empty table yields the type default
    # (1970-01-01), not NULL, which would poison the boundary/start logic.
    row = ch.query(f"SELECT minOrNull(timestamp) FROM {raw_ref}").first_row
    return _coerce_dt(row[0]) if row else None


def _live_boundary(ch: Any, overview_target: str, *, after: datetime) -> datetime:
    row = ch.query(f"SELECT minOrNull(bucket_ts) FROM {overview_target}").first_row
    live_min = _coerce_dt(row[0]) if row else None
    if live_min is not None:
        # live_min <= after means the live MV already saw the oldest raw row,
        # so there is nothing to backfill below it.
        return live_min if live_min > after else after
    return datetime.now(timezone.utc)


def _truncate_targets(ch: Any, *, facet_target: str, overview_target: str) -> None:
    ch.command(f"TRUNCATE TABLE IF EXISTS {facet_target}")
    ch.command(f"TRUNCATE TABLE IF EXISTS {overview_target}")


def _insert_chunk(
    ch: Any,
    *,
    db: str,
    table: str,
    facet_target: str,
    overview_target: str,
    lo: datetime,
    hi: datetime,
    gen: str,
) -> None:
    where = (
        f"timestamp >= toDateTime64('{_ch_literal(lo)}', 3, 'UTC') "
        f"AND timestamp < toDateTime64('{_ch_literal(hi)}', 3, 'UTC')"
    )
    slot = f"{gen}:{int(lo.timestamp())}:{int(hi.timestamp())}"
    ch.command(
        f"INSERT INTO {facet_target} " + proto_intel_facet_select_sql(db=db, table=table, where=where),
        settings={"insert_deduplication_token": f"pim:facet:{slot}"},
    )
    ch.command(
        f"INSERT INTO {overview_target} " + proto_intel_overview_select_sql(db=db, table=table, where=where),
        settings={"insert_deduplication_token": f"pim:overview:{slot}"},
    )


def _fill_descending(
    ch: Any,
    *,
    db: str,
    table: str,
    facet_target: str,
    overview_target: str,
    start: datetime,
    cursor: datetime,
    chunk_hours: int,
    gen: str,
    sleep_s: float,
) -> int:
    # Fill from the boundary down toward the oldest raw row, persisting the
    # floor after every chunk. Recent windows become MV-servable first and a
    # crash never discards completed work: the next cycle resumes at the floor.
    chunk = timedelta(hours=max(1, chunk_hours))
    lo_limit = start.astimezone(timezone.utc)
    hi = cursor.astimezone(timezone.utc)
    processed = 0
    while hi > lo_limit:
        lo = max(lo_limit, hi - chunk)
        _insert_chunk(
            ch,
            db=db,
            table=table,
            facet_target=facet_target,
            overview_target=overview_target,
            lo=lo,
            hi=hi,
            gen=gen,
        )
        write_proto_intel_materialization_floor(floor_ts=lo)
        processed += 1
        hi = lo
        if sleep_s and hi > lo_limit:
            time.sleep(sleep_s)
    return processed


def run_materialization(
    ch: Any,
    *,
    force: bool = False,
    chunk_hours: Optional[int] = None,
    sleep_s: Optional[float] = None,
) -> Optional[datetime]:
    raw_ref = clickhouse_events_table_ref()
    db, table = raw_ref.split(".", 1)
    facet_target = clickhouse_proto_intel_table_ref()
    overview_target = clickhouse_proto_intel_overview_table_ref()
    effective_chunk_hours = _settings_chunk_hours(chunk_hours)
    effective_sleep_s = _settings_sleep_s(sleep_s)

    if force:
        clear_proto_intel_materialization_state()
        _truncate_targets(ch, facet_target=facet_target, overview_target=overview_target)

    floor = None if force else read_proto_intel_materialization_floor()

    raw_min = _raw_min_ts(ch, raw_ref)
    if raw_min is None:
        return floor
    start = raw_min.replace(second=0, microsecond=0)

    if floor is not None and floor <= start:
        return floor

    rng = read_proto_intel_materialization_range()
    if floor is not None and rng is None:
        # A floor without its pinned range means the chunk grid that produced
        # the dedup tokens is gone; resuming on a new grid could double count
        # partially inserted blocks. Rebuild instead.
        floor = None

    if floor is None:
        # No usable progress marker: fresh install, or a previous fill crashed
        # before completing its first chunk. Partially inserted blocks may
        # exist, so rebuild under a new generation to keep exactly one copy of
        # every bucket.
        if not force:
            clear_proto_intel_materialization_state()
            _truncate_targets(ch, facet_target=facet_target, overview_target=overview_target)
        rng = pin_proto_intel_materialization_range(
            start_ts=start,
            boundary_ts=_live_boundary(ch, overview_target, after=start),
            chunk_hours=effective_chunk_hours,
        )
        if rng is None:
            return None
        cursor = rng["boundary"]
    else:
        # Resume below the persisted floor (also covers extension when older
        # rows appear in raw after a completed materialization).
        cursor = floor

    processed = _fill_descending(
        ch,
        db=db,
        table=table,
        facet_target=facet_target,
        overview_target=overview_target,
        start=start,
        cursor=cursor,
        # The pinned grid keeps chunk edges (and dedup tokens) stable across
        # retries even if the configured chunk size changes mid-flight.
        chunk_hours=int(rng.get("chunk_hours") or effective_chunk_hours),
        gen=str(rng.get("gen") or "0"),
        sleep_s=effective_sleep_s,
    )
    write_proto_intel_materialization_floor(floor_ts=start)
    log_event(
        logger,
        "info",
        "proto_intel_materialized",
        floor=start.isoformat(),
        boundary=cursor.isoformat(),
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

    ch = get_clickhouse_long_ops_client()
    t0 = time.time()
    try:
        floor = run_materialization(
            ch,
            force=_env_bool("SEAGULL_PROTO_INTEL_BACKFILL_FORCE", False),
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
