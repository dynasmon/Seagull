from __future__ import annotations

import logging

from app.core.observability import log_event
from app.features.correlations.worker_runtime import (
    CorrelationsWorkerConfig,
    load_enabled_rules,
    run_correlation_cycle,
)

from .state import CorrelationsWorkerState

logger = logging.getLogger("seagull.worker.correlations")


def run_once(cfg: CorrelationsWorkerConfig, state: CorrelationsWorkerState) -> bool:
    rules = load_enabled_rules()
    if not rules:
        if state.should_log_idle(cfg.log_every_seconds):
            log_event(logger, "info", "correlations_worker_idle", reason="no_enabled_rules")
            state.mark_idle_logged()
        return False

    result = run_correlation_cycle(cfg)
    state.cycle_count += 1

    if state.should_log_ok(cfg.log_every_seconds):
        log_event(
            logger,
            "info",
            "correlations_worker_ok",
            rules_evaluated=result.rules_evaluated,
            alerts_scanned=result.alerts_scanned,
            incidents_found=len(result.incidents),
            cycle=state.cycle_count,
        )
        state.mark_ok_logged()

    return True
