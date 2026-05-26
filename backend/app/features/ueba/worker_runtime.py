"""Worker-facing import surface for the UEBA feature."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from app.core.config.env_secrets import env_value
from app.core.db import SessionLocal
from app.features.ueba import lifecycle, maintenance, repository
from app.features.ueba.domain.registry import DetectorExecutionResult, UebaDetector, default_detectors

_LAST_MAINTENANCE_AT: datetime | None = None


def _env_int(name: str, default: int) -> int:
    raw = env_value(name, None)
    if raw is None:
        return int(default)
    try:
        return int(raw, 10)
    except (TypeError, ValueError):
        return int(default)


def _env_float(name: str, default: float) -> float:
    raw = env_value(name, None)
    if raw is None:
        return float(default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float(default)


@dataclass(frozen=True)
class UebaWorkerConfig:
    interval_seconds: float
    log_every_seconds: float
    failing_after: int
    cooldown_minutes: int
    max_findings_per_detector_cycle: int
    active_entity_hours: int

    login_hour_lookback_hours: int
    login_hour_min_samples: int
    login_hour_max_events_per_cycle: int
    login_hour_min_rarity_bits: float
    login_hour_min_z_score: float

    source_diversity_window_minutes: int
    source_diversity_min_samples: int
    source_diversity_max_entities_per_cycle: int
    source_diversity_max_windows_per_cycle: int
    source_diversity_min_z_score: float
    outbound_bytes_window_minutes: int
    outbound_bytes_min_samples: int
    outbound_bytes_max_entities_per_cycle: int
    outbound_bytes_max_windows_per_cycle: int
    outbound_bytes_min_z_score: float
    lateral_spread_window_minutes: int
    lateral_spread_min_samples: int
    lateral_spread_max_entities_per_cycle: int
    lateral_spread_max_windows_per_cycle: int
    lateral_spread_min_z_score: float
    proc_exec_rate_window_minutes: int
    proc_exec_rate_min_samples: int
    proc_exec_rate_max_entities_per_cycle: int
    proc_exec_rate_max_windows_per_cycle: int
    proc_exec_rate_min_z_score: float
    proc_name_lookback_hours: int
    proc_name_max_events_per_cycle: int
    proc_name_min_rarity_bits: float
    proc_name_min_samples_for_maturity: int
    proc_name_rarity_lookback_hours: int
    fim_spike_window_minutes: int
    fim_spike_min_samples: int
    fim_spike_max_entities_per_cycle: int
    fim_spike_max_windows_per_cycle: int
    fim_spike_min_z_score: float
    sudo_hour_lookback_hours: int
    sudo_hour_min_samples: int
    sudo_hour_max_events_per_cycle: int
    sudo_hour_min_rarity_bits: float
    sudo_hour_min_z_score: float
    if_training_min_samples: int
    if_retraining_interval_seconds: int
    if_model_stale_seconds: int
    if_model_retention_days: int
    if_model_cache_ttl_seconds: int
    if_weight: float
    rarity_weight: float
    if_n_estimators: int
    if_random_state: int
    if_feature_schema_version: int
    if_contamination: str
    peer_clustering_interval_seconds: int
    peer_group_retention_days: int
    peer_min_silhouette_score: float
    peer_distance_percentile: float
    peer_current_window_minutes: int
    peer_feature_schema_version: int
    peer_min_agents: int
    peer_min_mature_days: int
    peer_max_events_per_clustering: int


@dataclass(frozen=True)
class UebaDetectorCycleResult:
    detector_id: str
    detector_version: int
    status: str
    outcome: DetectorExecutionResult | None = None
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class UebaCycleResult:
    detectors: list[UebaDetectorCycleResult]

    @property
    def completed(self) -> int:
        return sum(1 for item in self.detectors if item.status == "completed")

    @property
    def failed(self) -> int:
        return sum(1 for item in self.detectors if item.status == "failed")

    @property
    def alerts_created(self) -> int:
        return sum(int(item.outcome.alerts_created) for item in self.detectors if item.outcome is not None)


def _load_contamination() -> str:
    raw = env_value("SEAGULL_UEBA_IF_CONTAMINATION", "auto")
    if raw != "auto":
        try:
            float(raw)
        except (TypeError, ValueError):
            return "auto"
    return raw


def load_worker_config() -> UebaWorkerConfig:
    return UebaWorkerConfig(
        interval_seconds=max(5.0, _env_float("SEAGULL_UEBA_INTERVAL_SECONDS", 60.0)),
        log_every_seconds=_env_float("SEAGULL_UEBA_LOG_EVERY_SECONDS", 60.0),
        failing_after=max(1, _env_int("SEAGULL_UEBA_FAILING_AFTER", 3)),
        cooldown_minutes=max(1, _env_int("SEAGULL_UEBA_COOLDOWN_MINUTES", 60)),
        max_findings_per_detector_cycle=max(0, _env_int("SEAGULL_UEBA_MAX_FINDINGS_PER_DETECTOR_CYCLE", 20)),
        active_entity_hours=max(1, _env_int("SEAGULL_UEBA_ACTIVE_ENTITY_HOURS", 24)),
        login_hour_lookback_hours=max(1, _env_int("SEAGULL_UEBA_LOGIN_HOUR_LOOKBACK_HOURS", 72)),
        login_hour_min_samples=max(4, _env_int("SEAGULL_UEBA_LOGIN_HOUR_MIN_SAMPLES", 20)),
        login_hour_max_events_per_cycle=max(1, _env_int("SEAGULL_UEBA_LOGIN_HOUR_MAX_EVENTS_PER_CYCLE", 500)),
        login_hour_min_rarity_bits=max(0.0, _env_float("SEAGULL_UEBA_LOGIN_HOUR_MIN_RARITY_BITS", 3.0)),
        login_hour_min_z_score=max(0.0, _env_float("SEAGULL_UEBA_LOGIN_HOUR_MIN_Z_SCORE", 2.5)),
        source_diversity_window_minutes=max(1, _env_int("SEAGULL_UEBA_SOURCE_DIVERSITY_WINDOW_MINUTES", 15)),
        source_diversity_min_samples=max(4, _env_int("SEAGULL_UEBA_SOURCE_DIVERSITY_MIN_SAMPLES", 12)),
        source_diversity_max_entities_per_cycle=max(
            1,
            _env_int("SEAGULL_UEBA_SOURCE_DIVERSITY_MAX_ENTITIES_PER_CYCLE", 500),
        ),
        source_diversity_max_windows_per_cycle=max(
            1,
            _env_int("SEAGULL_UEBA_SOURCE_DIVERSITY_MAX_WINDOWS_PER_CYCLE", 4),
        ),
        source_diversity_min_z_score=max(0.0, _env_float("SEAGULL_UEBA_SOURCE_DIVERSITY_MIN_Z_SCORE", 3.0)),
        outbound_bytes_window_minutes=max(1, _env_int("SEAGULL_UEBA_OUTBOUND_BYTES_WINDOW_MINUTES", 15)),
        outbound_bytes_min_samples=max(1, _env_int("SEAGULL_UEBA_OUTBOUND_BYTES_MIN_SAMPLES", 10)),
        outbound_bytes_max_entities_per_cycle=max(1, _env_int("SEAGULL_UEBA_OUTBOUND_BYTES_MAX_ENTITIES_PER_CYCLE", 200)),
        outbound_bytes_max_windows_per_cycle=max(1, _env_int("SEAGULL_UEBA_OUTBOUND_BYTES_MAX_WINDOWS_PER_CYCLE", 4)),
        outbound_bytes_min_z_score=max(0.0, _env_float("SEAGULL_UEBA_OUTBOUND_BYTES_MIN_Z_SCORE", 3.5)),
        lateral_spread_window_minutes=max(1, _env_int("SEAGULL_UEBA_LATERAL_SPREAD_WINDOW_MINUTES", 15)),
        lateral_spread_min_samples=max(1, _env_int("SEAGULL_UEBA_LATERAL_SPREAD_MIN_SAMPLES", 8)),
        lateral_spread_max_entities_per_cycle=max(1, _env_int("SEAGULL_UEBA_LATERAL_SPREAD_MAX_ENTITIES_PER_CYCLE", 200)),
        lateral_spread_max_windows_per_cycle=max(1, _env_int("SEAGULL_UEBA_LATERAL_SPREAD_MAX_WINDOWS_PER_CYCLE", 4)),
        lateral_spread_min_z_score=max(0.0, _env_float("SEAGULL_UEBA_LATERAL_SPREAD_MIN_Z_SCORE", 3.0)),
        proc_exec_rate_window_minutes=max(1, _env_int("SEAGULL_UEBA_PROC_EXEC_RATE_WINDOW_MINUTES", 5)),
        proc_exec_rate_min_samples=max(1, _env_int("SEAGULL_UEBA_PROC_EXEC_RATE_MIN_SAMPLES", 12)),
        proc_exec_rate_max_entities_per_cycle=max(1, _env_int("SEAGULL_UEBA_PROC_EXEC_RATE_MAX_ENTITIES_PER_CYCLE", 200)),
        proc_exec_rate_max_windows_per_cycle=max(1, _env_int("SEAGULL_UEBA_PROC_EXEC_RATE_MAX_WINDOWS_PER_CYCLE", 6)),
        proc_exec_rate_min_z_score=max(0.0, _env_float("SEAGULL_UEBA_PROC_EXEC_RATE_MIN_Z_SCORE", 4.0)),
        proc_name_lookback_hours=max(1, _env_int("SEAGULL_UEBA_PROC_NAME_LOOKBACK_HOURS", 72)),
        proc_name_max_events_per_cycle=max(1, _env_int("SEAGULL_UEBA_PROC_NAME_MAX_EVENTS_PER_CYCLE", 1000)),
        proc_name_min_rarity_bits=max(0.0, _env_float("SEAGULL_UEBA_PROC_NAME_MIN_RARITY_BITS", 4.0)),
        proc_name_min_samples_for_maturity=max(1, _env_int("SEAGULL_UEBA_PROC_NAME_MIN_SAMPLES_FOR_MATURITY", 5)),
        proc_name_rarity_lookback_hours=max(1, _env_int("SEAGULL_UEBA_PROC_NAME_RARITY_LOOKBACK_HOURS", 168)),
        fim_spike_window_minutes=max(1, _env_int("SEAGULL_UEBA_FIM_SPIKE_WINDOW_MINUTES", 5)),
        fim_spike_min_samples=max(1, _env_int("SEAGULL_UEBA_FIM_SPIKE_MIN_SAMPLES", 10)),
        fim_spike_max_entities_per_cycle=max(1, _env_int("SEAGULL_UEBA_FIM_SPIKE_MAX_ENTITIES_PER_CYCLE", 100)),
        fim_spike_max_windows_per_cycle=max(1, _env_int("SEAGULL_UEBA_FIM_SPIKE_MAX_WINDOWS_PER_CYCLE", 6)),
        fim_spike_min_z_score=max(0.0, _env_float("SEAGULL_UEBA_FIM_SPIKE_MIN_Z_SCORE", 4.0)),
        sudo_hour_lookback_hours=max(1, _env_int("SEAGULL_UEBA_SUDO_HOUR_LOOKBACK_HOURS", 72)),
        sudo_hour_min_samples=max(1, _env_int("SEAGULL_UEBA_SUDO_HOUR_MIN_SAMPLES", 15)),
        sudo_hour_max_events_per_cycle=max(1, _env_int("SEAGULL_UEBA_SUDO_HOUR_MAX_EVENTS_PER_CYCLE", 500)),
        sudo_hour_min_rarity_bits=max(0.0, _env_float("SEAGULL_UEBA_SUDO_HOUR_MIN_RARITY_BITS", 3.0)),
        sudo_hour_min_z_score=max(0.0, _env_float("SEAGULL_UEBA_SUDO_HOUR_MIN_Z_SCORE", 2.5)),
        if_training_min_samples=max(10, _env_int("SEAGULL_UEBA_IF_TRAINING_MIN_SAMPLES", 500)),
        if_retraining_interval_seconds=max(60, _env_int("SEAGULL_UEBA_IF_RETRAINING_INTERVAL_SECONDS", 21_600)),
        if_model_stale_seconds=max(60, _env_int("SEAGULL_UEBA_IF_MODEL_STALE_SECONDS", 86_400)),
        if_model_retention_days=max(1, _env_int("SEAGULL_UEBA_IF_MODEL_RETENTION_DAYS", 30)),
        if_model_cache_ttl_seconds=max(1, _env_int("SEAGULL_UEBA_IF_MODEL_CACHE_TTL_SECONDS", 300)),
        if_weight=min(1.0, max(0.0, _env_float("SEAGULL_UEBA_IF_BLEND_WEIGHT", 0.6))),
        rarity_weight=min(1.0, max(0.0, _env_float("SEAGULL_UEBA_RARITY_BLEND_WEIGHT", 0.4))),
        if_n_estimators=max(10, _env_int("SEAGULL_UEBA_IF_N_ESTIMATORS", 200)),
        if_random_state=_env_int("SEAGULL_UEBA_IF_RANDOM_STATE", 42),
        if_feature_schema_version=max(1, _env_int("SEAGULL_UEBA_IF_FEATURE_SCHEMA_VERSION", 1)),
        if_contamination=_load_contamination(),
        peer_clustering_interval_seconds=max(
            60,
            _env_int("SEAGULL_UEBA_PEER_CLUSTERING_INTERVAL_SECONDS", 21_600),
        ),
        peer_group_retention_days=max(1, _env_int("SEAGULL_UEBA_PEER_GROUP_RETENTION_DAYS", 90)),
        peer_min_silhouette_score=max(0.0, _env_float("SEAGULL_UEBA_PEER_MIN_SILHOUETTE_SCORE", 0.25)),
        peer_distance_percentile=min(99.9, max(50.0, _env_float("SEAGULL_UEBA_PEER_DISTANCE_PERCENTILE", 95.0))),
        peer_current_window_minutes=max(5, _env_int("SEAGULL_UEBA_PEER_CURRENT_WINDOW_MINUTES", 60)),
        peer_feature_schema_version=max(1, _env_int("SEAGULL_UEBA_PEER_FEATURE_SCHEMA_VERSION", 1)),
        peer_min_agents=max(2, _env_int("SEAGULL_UEBA_PEER_MIN_AGENTS", 4)),
        peer_min_mature_days=max(0, _env_int("SEAGULL_UEBA_PEER_MIN_MATURE_DAYS", 3)),
        peer_max_events_per_clustering=max(1000, _env_int("SEAGULL_UEBA_PEER_MAX_EVENTS_PER_CLUSTERING", 50_000)),
    )


def run_ueba_cycle(
    cfg: UebaWorkerConfig,
    *,
    now: datetime | None = None,
    detector_set: Iterable[UebaDetector] | None = None,
) -> UebaCycleResult:
    cycle_now = _as_utc(now or datetime.now(timezone.utc))
    _run_maintenance_if_due(cfg, now=cycle_now)
    detectors = list(detector_set or default_detectors())
    results: list[UebaDetectorCycleResult] = []
    for detector in detectors:
        results.append(_run_one_detector(detector, cfg=cfg, now=cycle_now))
    return UebaCycleResult(detectors=results)


def _run_maintenance_if_due(cfg: UebaWorkerConfig, *, now: datetime) -> None:
    global _LAST_MAINTENANCE_AT
    interval = min(
        max(60, int(cfg.if_retraining_interval_seconds)),
        max(60, int(cfg.peer_clustering_interval_seconds)),
    )
    if _LAST_MAINTENANCE_AT is not None and (_LAST_MAINTENANCE_AT + timedelta(seconds=interval)) > now:
        return
    db = SessionLocal()
    try:
        maintenance.run_ueba_maintenance(db, cfg=cfg, now=now)
        repository.commit(db)
        _LAST_MAINTENANCE_AT = now
    except Exception:
        db.rollback()
    finally:
        db.close()


def _run_one_detector(detector: UebaDetector, *, cfg: UebaWorkerConfig, now: datetime) -> UebaDetectorCycleResult:
    db = SessionLocal()
    run = None
    try:
        window_started_at, window_ended_at = detector.window_bounds(db, cfg=cfg, now=now)
        run = lifecycle.start_detector_run(
            db,
            detector_id=detector.detector_id,
            detector_version=detector.detector_version,
            started_at=now,
            window_started_at=window_started_at,
            window_ended_at=window_ended_at,
            context={"source": "postgres"},
        )
        repository.flush(db)
        repository.commit(db)

        outcome = detector.run(db, cfg=cfg, now=now)
        _merge_detector_context(db, detector.detector_id, outcome.state_context_patch)
        baseline_count, mature_count = repository.count_detector_baselines(db, detector.detector_id)
        open_findings = repository.count_open_findings_for_detector(db, detector.detector_id)
        lifecycle.complete_detector_run(
            db,
            run=run,
            finished_at=now,
            scanned_events=outcome.scanned_events,
            evaluated_entities=outcome.evaluated_entities,
            baselines_created=outcome.baselines_created,
            baselines_updated=outcome.baselines_updated,
            findings_created=outcome.findings_created,
            findings_updated=outcome.findings_updated,
            alerts_created=outcome.alerts_created,
            suppressions_applied=outcome.suppressions_applied,
            baseline_count=baseline_count,
            mature_baseline_count=mature_count,
            open_findings=open_findings,
            context_patch=outcome.run_context_patch,
        )
        repository.commit(db)
        return UebaDetectorCycleResult(
            detector_id=detector.detector_id,
            detector_version=detector.detector_version,
            status="completed",
            outcome=outcome,
        )
    except Exception as exc:
        db.rollback()
        try:
            if run is None:
                window_started_at, window_ended_at = detector.window_bounds(db, cfg=cfg, now=now)
                run = lifecycle.start_detector_run(
                    db,
                    detector_id=detector.detector_id,
                    detector_version=detector.detector_version,
                    started_at=now,
                    window_started_at=window_started_at,
                    window_ended_at=window_ended_at,
                    context={"source": "postgres", "failed_before_execution": True},
                )
                repository.flush(db)
            else:
                run = repository.get_detector_run(db, int(run.id)) or run
            lifecycle.fail_detector_run(
                db,
                run=run,
                failed_at=now,
                error_type=type(exc).__name__,
                error_message=str(exc),
                failing_after=cfg.failing_after,
                context_patch={"source": "postgres"},
            )
            repository.commit(db)
        except Exception:
            db.rollback()
        return UebaDetectorCycleResult(
            detector_id=detector.detector_id,
            detector_version=detector.detector_version,
            status="failed",
            error_type=type(exc).__name__,
            error_message=str(exc),
        )
    finally:
        db.close()


def _merge_detector_context(db, detector_id: str, patch: dict | None) -> None:
    if not patch:
        return
    existing = repository.get_detector_state(db, detector_id)
    merged = dict(getattr(existing, "context", None) or {})
    merged.update(dict(patch or {}))
    lifecycle.upsert_detector_state(
        db,
        detector_id=detector_id,
        detector_version=getattr(existing, "detector_version", None),
        context=merged,
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = [
    "UebaCycleResult",
    "UebaDetectorCycleResult",
    "UebaWorkerConfig",
    "load_worker_config",
    "run_ueba_cycle",
]
