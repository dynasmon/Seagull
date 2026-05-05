"""Worker-facing import surface for the correlations feature.

Worker code imports only from here — not from deep internal paths.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config.env_secrets import env_value


def _env_int(name: str, default: int) -> int:
    v = env_value(name, None)
    if v is None:
        return default
    try:
        return int(v, 10)
    except (ValueError, TypeError):
        return default


def _env_float(name: str, default: float) -> float:
    v = env_value(name, None)
    if v is None:
        return default
    try:
        return float(v)
    except (ValueError, TypeError):
        return default


@dataclass(frozen=True)
class CorrelationsWorkerConfig:
    interval_seconds: float
    max_alerts: int
    max_age_minutes: int
    log_every_seconds: float


def load_worker_config() -> CorrelationsWorkerConfig:
    return CorrelationsWorkerConfig(
        interval_seconds=max(5.0, _env_float("SEAGULL_CORRELATIONS_INTERVAL_SECONDS", 60.0)),
        max_alerts=max(1, _env_int("SEAGULL_CORRELATIONS_MAX_ALERTS", 5000)),
        max_age_minutes=max(1, _env_int("SEAGULL_CORRELATIONS_MAX_AGE_MINUTES", 60)),
        log_every_seconds=_env_float("SEAGULL_CORRELATIONS_LOG_EVERY_SECONDS", 60.0),
    )


def load_enabled_rules() -> list:
    from app.core.db import SessionLocal
    from app.features.correlations.repository import list_enabled_rules as _list_enabled_rules

    db = SessionLocal()
    try:
        return _list_enabled_rules(db)
    finally:
        db.close()


def run_correlation_cycle(cfg: CorrelationsWorkerConfig):
    from app.core.db import SessionLocal
    from app.features.correlations.service import run_correlations as _run_correlations

    db = SessionLocal()
    try:
        return _run_correlations(
            db,
            limit=cfg.max_alerts,
            max_age_minutes=cfg.max_age_minutes,
            sample_limit=50,
        )
    finally:
        db.close()


__all__ = [
    "CorrelationsWorkerConfig",
    "load_enabled_rules",
    "load_worker_config",
    "run_correlation_cycle",
]
