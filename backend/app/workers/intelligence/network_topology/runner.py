from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from app.core.config.env_secrets import env_value
from app.core.db import SessionLocal
from app.core.observability import log_event
from app.features.network_topology import realtime as topology_realtime
from app.features.network_topology.service import run_recalculation

from .state import NetworkTopologyWorkerState

logger = logging.getLogger("seagull.worker.network_topology")


def _env_bool(name: str, default: bool) -> bool:
    raw = env_value(name, None)
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    raw = env_value(name, None)
    if raw is None:
        return default
    try:
        return int(str(raw).strip(), 10)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = env_value(name, None)
    if raw is None:
        return default
    try:
        return float(str(raw).strip())
    except Exception:
        return default


@dataclass(frozen=True)
class NetworkTopologyWorkerConfig:
    enabled: bool
    refresh_seconds: float
    window_minutes: int
    stale_after_minutes: int
    max_events_per_run: int
    log_every_seconds: float = 60.0


def load_worker_config() -> NetworkTopologyWorkerConfig:
    return NetworkTopologyWorkerConfig(
        enabled=_env_bool("SEAGULL_NETWORK_TOPOLOGY_ENABLED", True),
        refresh_seconds=max(10.0, _env_float("SEAGULL_NETWORK_TOPOLOGY_REFRESH_SECONDS", 300.0)),
        window_minutes=max(5, _env_int("SEAGULL_NETWORK_TOPOLOGY_WINDOW_MINUTES", 1440)),
        stale_after_minutes=max(1, _env_int("SEAGULL_NETWORK_TOPOLOGY_STALE_AFTER_MINUTES", 15)),
        max_events_per_run=max(100, _env_int("SEAGULL_NETWORK_TOPOLOGY_MAX_EVENTS_PER_RUN", 5000)),
        log_every_seconds=max(0.0, _env_float("SEAGULL_NETWORK_TOPOLOGY_LOG_EVERY_SECONDS", 60.0)),
    )


def run_once(cfg: NetworkTopologyWorkerConfig, state: NetworkTopologyWorkerState) -> bool:
    request = topology_realtime.load_recalculation_request()
    token = _request_token(request)
    if token and token != state.last_recalc_token and token != state.pending_recalc_token:
        state.pending_recalc_token = token
        state.pending_reason = str((request or {}).get("reason") or "requested")
        log_event(
            logger,
            "info",
            "network_topology_recalc_requested",
            requested_at=(request or {}).get("requested_at"),
            requested_by=(request or {}).get("requested_by"),
            reason=state.pending_reason,
        )

    now_t = time.time()
    periodic_due = state.last_refresh_t <= 0 or (now_t - state.last_refresh_t) >= cfg.refresh_seconds
    trigger_interval = max(60.0, min(cfg.refresh_seconds, 600.0))
    trigger_due = bool(state.pending_recalc_token) and (
        state.last_refresh_t <= 0 or (now_t - state.last_refresh_t) >= trigger_interval
    )

    if not periodic_due and not trigger_due:
        if state.should_log_idle(cfg.log_every_seconds):
            log_event(
                logger,
                "info",
                "network_topology_worker_idle",
                refresh_in_seconds=round(max(0.0, cfg.refresh_seconds - (now_t - state.last_refresh_t)), 3),
                pending_recalculate=bool(state.pending_recalc_token),
            )
            state.mark_idle_logged()
        return False

    reason = state.pending_reason if trigger_due else "periodic"
    result = _run_recalculation_cycle(cfg, reason=reason)
    state.cycle_count += 1
    state.last_refresh_t = time.time()
    if state.pending_recalc_token:
        state.last_recalc_token = state.pending_recalc_token
        state.pending_recalc_token = ""
        state.pending_reason = ""

    if state.should_log_ok(cfg.log_every_seconds):
        log_event(
            logger,
            "info",
            "network_topology_worker_ok",
            projected_nodes=result.projected_nodes,
            projected_edges=result.projected_edges,
            duration_ms=result.duration_ms,
            window_minutes=cfg.window_minutes,
            max_events_per_run=cfg.max_events_per_run,
            cycle=state.cycle_count,
        )
        state.mark_ok_logged()
    return True


def _run_recalculation_cycle(cfg: NetworkTopologyWorkerConfig, *, reason: str):
    db = SessionLocal()
    try:
        return run_recalculation(
            db,
            projected_by="network_topology_worker",
            reason=reason,
            window_minutes=cfg.window_minutes,
            max_events_per_run=cfg.max_events_per_run,
        )
    finally:
        db.close()


def _request_token(request: dict[str, Any] | None) -> str:
    if not isinstance(request, dict):
        return ""
    token = str(request.get("requested_at") or "").strip()
    if not token:
        token = str(request.get("request_id") or "").strip()
    return token

