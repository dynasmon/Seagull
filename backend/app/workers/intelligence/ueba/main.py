from __future__ import annotations

import logging
import time

from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.observability import log_event, setup_logging
from app.features.ueba.worker_runtime import load_worker_config

from .runner import run_once
from .state import UebaWorkerState

setup_logging("worker-ueba")
logger = logging.getLogger("seagull.worker.ueba")


def main() -> None:
    settings.validate_for_service("worker-ueba")
    cfg = load_worker_config()
    state = UebaWorkerState()
    backoff = 1.0

    log_event(
        logger,
        "info",
        "ueba_worker_start",
        interval_s=cfg.interval_seconds,
        login_hour_min_samples=cfg.login_hour_min_samples,
        source_diversity_window_minutes=cfg.source_diversity_window_minutes,
        source_diversity_min_samples=cfg.source_diversity_min_samples,
        max_findings_per_detector_cycle=cfg.max_findings_per_detector_cycle,
    )

    while True:
        try:
            run_once(cfg, state)
            backoff = 1.0
            time.sleep(cfg.interval_seconds)
        except KeyboardInterrupt:
            raise
        except OperationalError as exc:
            wait_s = min(backoff, 15.0)
            log_event(
                logger,
                "warning",
                "ueba_worker_error",
                reason="db_not_ready",
                wait_s=wait_s,
                error=str(exc).splitlines()[0],
            )
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as exc:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "ueba_worker_error", wait_s=wait_s, error=repr(exc))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
