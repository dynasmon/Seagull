from __future__ import annotations

import asyncio
import logging
import time

from app.core.cache import get_redis
from app.core.config import settings
from app.core.observability import incr_counter, log_event, setup_logging
from app.features.events import service as events_service  # noqa: F401
from app.shared.analytics import get_read_model, iter_warm_specs, serve_read_model

setup_logging("worker-proto-prewarm")
logger = logging.getLogger("seagull.worker.proto_prewarm")


def _clickhouse_busy() -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        state = r.get("seagull:ingest:clickhouse:state")
    except Exception:
        return False
    return str(state or "").strip().lower() == "degraded"


async def _warm_once() -> tuple[int, int]:
    ok = 0
    err = 0
    for spec in iter_warm_specs():
        model = get_read_model(spec.feature)
        if model is None:
            continue
        try:
            await serve_read_model(model, dict(spec.params), allow_stale=False, background=False)
            incr_counter("analytics_prewarm_total", feature=spec.feature, outcome="ok")
            ok += 1
        except Exception as exc:
            incr_counter("analytics_prewarm_total", feature=spec.feature, outcome="error")
            err += 1
            log_event(
                logger,
                "warning",
                "prewarm_spec_error",
                feature=spec.feature,
                error_type=type(exc).__name__,
            )
    return ok, err


def main() -> int:
    settings.validate_for_service("worker-proto-prewarm")

    if not bool(getattr(settings, "SEAGULL_ANALYTICS_PREWARM_ENABLED", True)):
        log_event(logger, "info", "prewarm_disabled")
        return 0

    every_s = max(5.0, float(getattr(settings, "SEAGULL_ANALYTICS_PREWARM_EVERY_SECONDS", 120.0) or 120.0))

    while True:
        try:
            if _clickhouse_busy():
                log_event(logger, "info", "prewarm_backoff_clickhouse_busy")
                time.sleep(min(every_s * 2.0, 120.0))
                continue

            t0 = time.time()
            ok, err = asyncio.run(_warm_once())
            log_event(
                logger,
                "info",
                "prewarm_cycle_ok",
                warmed=ok,
                errors=err,
                took_ms=int((time.time() - t0) * 1000),
            )
            time.sleep(every_s)
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            log_event(logger, "error", "prewarm_loop_error", error_type=type(exc).__name__)
            time.sleep(min(every_s, 30.0))


if __name__ == "__main__":
    raise SystemExit(main())
