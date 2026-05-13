from __future__ import annotations

import logging
import time

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.db.lifecycle import ensure_database_ready
from app.core.observability import log_event, setup_logging

from .runner import load_worker_config, run_once
from .state import NetworkTopologyWorkerState

setup_logging("worker-network-topology")
logger = logging.getLogger("seagull.worker.network_topology")


def main() -> None:
    settings.validate_for_service("worker-network-topology")
    cfg = load_worker_config()
    if not cfg.enabled:
        log_event(logger, "info", "network_topology_worker_disabled")
        return

    ensure_database_ready()
    state = NetworkTopologyWorkerState()
    backoff = 1.0
    idle_sleep = 15.0

    log_event(
        logger,
        "info",
        "network_topology_worker_start",
        refresh_seconds=cfg.refresh_seconds,
        window_minutes=cfg.window_minutes,
        stale_after_minutes=cfg.stale_after_minutes,
        max_events_per_run=cfg.max_events_per_run,
    )

    while True:
        try:
            run_once(cfg, state)
            backoff = 1.0
            time.sleep(idle_sleep)
        except KeyboardInterrupt:
            raise
        except OperationalError as exc:
            wait_s = min(backoff, 15.0)
            log_event(
                logger,
                "warning",
                "network_topology_worker_error",
                reason="db_not_ready",
                wait_s=wait_s,
                error=str(exc).splitlines()[0],
            )
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as exc:
            wait_s = min(backoff, 30.0)
            log_event(
                logger,
                "error",
                "network_topology_worker_error",
                wait_s=wait_s,
                error=repr(exc),
            )
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()

