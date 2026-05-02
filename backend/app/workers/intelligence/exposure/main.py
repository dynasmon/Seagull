"""Exposure Graph worker.

Reads net_events incrementally and runs periodic full posture refreshes.
Projects agent, inventory, vulnerability, alert, attack-chain, and event
signals into the exposure graph tables.
"""

from __future__ import annotations

import logging
import time
from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.core.observability import log_event, setup_logging
from app.features.exposure.realtime import load_recalculation_request
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset

from .posture import _run_posture_refresh
from .projector import _fetch_events, _get_max_event_id, _process_event_batch

OFFSET_NAME = "exposure_graph_events_v1"
RECALC_REQUEST_KEY = "seagull:exposure:recalc:request"

setup_logging("worker-exposure-graph")
logger = logging.getLogger("seagull.worker.exposure_graph")


def _ensure_bootstrap() -> None:
    ensure_database_ready()
    with engine.begin() as conn:
        ensure_offset(OFFSET_NAME, conn=conn)


def _get_last_id() -> int:
    ensure_offset(OFFSET_NAME)
    return get_offset(OFFSET_NAME)


def _set_last_id(last_id: int) -> None:
    set_offset(OFFSET_NAME, last_id)


def main() -> None:
    settings.validate_for_service("worker-exposure-graph")
    if not settings.SEAGULL_EXPOSURE_ENABLED:
        log_event(logger, "info", "exposure_graph_disabled")
        return

    _ensure_bootstrap()

    every = float(settings.SEAGULL_EXPOSURE_EVERY_SECONDS)
    batch_size = int(settings.SEAGULL_EXPOSURE_EVENT_BATCH_SIZE)

    log_event(
        logger,
        "info",
        "exposure_graph_start",
        every_s=every,
        batch_size=batch_size,
        lookback_hours=settings.SEAGULL_EXPOSURE_LOOKBACK_HOURS,
        stale_agent_minutes=settings.SEAGULL_EXPOSURE_STALE_AGENT_MINUTES,
        stale_inventory_hours=settings.SEAGULL_EXPOSURE_STALE_INVENTORY_HOURS,
    )

    backoff = 1.0
    last_id = 0
    last_refresh_t = 0.0
    last_idle_log_t = 0.0
    last_recalc_token = ""
    idle_sleep = 5.0

    while True:
        try:
            if last_id == 0:
                last_id = _get_last_id()

            recalc_request = load_recalculation_request(RECALC_REQUEST_KEY)
            recalc_token = str((recalc_request or {}).get("requested_at") or "")
            if recalc_token and recalc_token != last_recalc_token:
                last_recalc_token = recalc_token
                last_refresh_t = 0.0
                log_event(
                    logger,
                    "info",
                    "exposure_graph_recalc_requested",
                    requested_at=recalc_request.get("requested_at"),
                    requested_by=recalc_request.get("requested_by"),
                    mode=recalc_request.get("mode"),
                )

            # Incremental event processing
            events = _fetch_events(last_id, batch_size)
            if events:
                t0 = time.time()
                new_last, ev_stats = _process_event_batch(events)
                if new_last and new_last > last_id:
                    last_id = new_last
                    _set_last_id(last_id)
                took_ms = int((time.time() - t0) * 1000)
                log_event(
                    logger,
                    "info",
                    "exposure_graph_events_ok",
                    last_id=last_id,
                    took_ms=took_ms,
                    **ev_stats,
                )
                backoff = 1.0
            else:
                now_t = time.time()
                if (now_t - last_idle_log_t) >= 30.0:
                    max_id = _get_max_event_id()
                    lag = max(0, int(max_id) - int(last_id))
                    log_event(
                        logger,
                        "info",
                        "exposure_graph_idle",
                        last_id=last_id,
                        max_id=max_id,
                        lag=lag,
                    )
                    last_idle_log_t = now_t

            # Periodic full posture refresh
            now_t = time.time()
            if every > 0 and (now_t - last_refresh_t) >= every:
                t0 = time.time()
                refresh_stats = _run_posture_refresh()
                took_ms = int((time.time() - t0) * 1000)
                last_refresh_t = time.time()
                log_event(
                    logger,
                    "info",
                    "exposure_graph_refresh_ok",
                    took_ms=took_ms,
                    **refresh_stats,
                )
                backoff = 1.0

            time.sleep(idle_sleep)

        except KeyboardInterrupt:
            raise
        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "exposure_graph_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "exposure_graph_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
