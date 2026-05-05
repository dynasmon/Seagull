from __future__ import annotations

import logging
import time

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.observability import log_event, setup_logging
from app.features.correlations.worker_runtime import load_worker_config

from .runner import run_once
from .state import CorrelationsWorkerState

setup_logging("worker-correlations")
logger = logging.getLogger("seagull.worker.correlations")


def main() -> None:
    settings.validate_for_service("worker-correlations")
    cfg = load_worker_config()
    state = CorrelationsWorkerState()
    backoff = 1.0

    log_event(
        logger,
        "info",
        "correlations_worker_start",
        interval_s=cfg.interval_seconds,
        max_alerts=cfg.max_alerts,
        max_age_minutes=cfg.max_age_minutes,
        log_every_s=cfg.log_every_seconds,
    )

    while True:
        try:
            run_once(cfg, state)
            backoff = 1.0
            time.sleep(cfg.interval_seconds)
        except KeyboardInterrupt:
            raise
        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(
                logger,
                "warning",
                "correlations_worker_error",
                reason="db_not_ready",
                wait_s=wait_s,
                error=str(e).splitlines()[0],
            )
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 30.0)
            log_event(
                logger,
                "error",
                "correlations_worker_error",
                wait_s=wait_s,
                error=repr(e),
            )
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
