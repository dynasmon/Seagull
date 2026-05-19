from __future__ import annotations

import logging

from app.core.observability import log_event
from app.features.ueba.worker_runtime import UebaWorkerConfig, run_ueba_cycle

from .state import UebaWorkerState

logger = logging.getLogger("seagull.worker.ueba")


def run_once(cfg: UebaWorkerConfig, state: UebaWorkerState):
    result = run_ueba_cycle(cfg)
    state.cycle_count += 1
    if state.should_log_ok(cfg.log_every_seconds):
        log_event(
            logger,
            "info",
            "ueba_worker_cycle",
            cycle=state.cycle_count,
            detectors_total=len(result.detectors),
            detectors_completed=result.completed,
            detectors_failed=result.failed,
            alerts_created=result.alerts_created,
            detector_results=[
                {
                    "detector_id": item.detector_id,
                    "status": item.status,
                    "scanned_events": (item.outcome.scanned_events if item.outcome is not None else None),
                    "evaluated_entities": (item.outcome.evaluated_entities if item.outcome is not None else None),
                    "findings_created": (item.outcome.findings_created if item.outcome is not None else None),
                    "alerts_created": (item.outcome.alerts_created if item.outcome is not None else None),
                    "error_type": item.error_type,
                }
                for item in result.detectors
            ],
        )
        state.mark_ok_logged()
    return result
