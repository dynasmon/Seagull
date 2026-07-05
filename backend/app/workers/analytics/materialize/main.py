from __future__ import annotations

import logging
import time

from app.core.cache import get_redis
from app.core.config import settings
from app.core.integrations.clickhouse import (
    clickhouse_is_available,
    clickhouse_is_enabled,
    ensure_clickhouse_events_schema,
    get_clickhouse_long_ops_client,
)
from app.core.observability import incr_counter, log_event, setup_logging
from app.workers.analytics.proto_intel_backfill import run_materialization

setup_logging("worker-proto-materialize")
logger = logging.getLogger("seagull.worker.proto_materialize")


def _clickhouse_busy() -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        return str(r.get("seagull:ingest:clickhouse:state") or "").strip().lower() == "degraded"
    except Exception:
        return False


def _reconcile_once() -> bool:
    if not ensure_clickhouse_events_schema():
        return False
    # Long-ops client: chunk INSERT ... SELECT statements can legitimately take
    # longer than the interactive send/receive timeout.
    ch = get_clickhouse_long_ops_client()
    floor = run_materialization(ch)
    return floor is not None


def main() -> int:
    settings.validate_for_service("worker-proto-materialize")

    if not bool(getattr(settings, "SEAGULL_ANALYTICS_MATERIALIZE_ENABLED", True)):
        log_event(logger, "info", "materialize_disabled")
        return 0

    every_s = max(30.0, float(getattr(settings, "SEAGULL_ANALYTICS_MATERIALIZE_EVERY_SECONDS", 300.0) or 300.0))

    while True:
        try:
            if not clickhouse_is_enabled():
                log_event(logger, "info", "materialize_clickhouse_disabled")
                return 0
            if not clickhouse_is_available() or _clickhouse_busy():
                time.sleep(min(every_s, 60.0))
                continue

            t0 = time.time()
            ok = _reconcile_once()
            incr_counter("analytics_materialize_total", outcome="ok" if ok else "skip")
            log_event(
                logger,
                "info",
                "materialize_cycle_ok",
                materialized=ok,
                took_ms=int((time.time() - t0) * 1000),
            )
            time.sleep(every_s)
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            incr_counter("analytics_materialize_total", outcome="error")
            log_event(logger, "error", "materialize_loop_error", error_type=type(exc).__name__)
            # Progress is persisted per chunk, so there is no benefit in
            # retrying aggressively; a tight error loop is how the CPU spiral
            # started in the first place.
            time.sleep(every_s)


if __name__ == "__main__":
    raise SystemExit(main())
