from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.observability import log_event
from app.features.ueba import repository
from app.features.ueba.domain import event_queries, ml

logger = logging.getLogger("seagull.ueba.maintenance")


def run_ueba_maintenance(db: Session, *, cfg: Any, now: datetime) -> dict[str, int]:
    now_v = _as_utc(now)
    expired_suppressions = repository.sweep_expired_suppressions(db, now=now_v)
    superseded_models = repository.sweep_superseded_ml_models(
        db,
        cutoff=now_v - timedelta(days=max(1, int(getattr(cfg, "if_model_retention_days", 30)))),
    )
    old_peer_groups = repository.sweep_peer_groups(
        db,
        cutoff=now_v - timedelta(days=max(1, int(getattr(cfg, "peer_group_retention_days", 90)))),
    )
    trained_models = train_stale_isolation_forest_models(db, cfg=cfg, now=now_v)
    result = {
        "expired_suppressions": int(expired_suppressions),
        "superseded_models": int(superseded_models),
        "old_peer_groups": int(old_peer_groups),
        "trained_models": int(trained_models),
    }
    log_event(logger, "info", "ueba_maintenance_sweep", **result)
    return result


def train_stale_isolation_forest_models(db: Session, *, cfg: Any, now: datetime) -> int:
    detector_id = "rare_process_name_v1"
    model_type = ml.MODEL_TYPE_ISOLATION_FOREST
    agents = repository.list_mature_agent_ids(db)
    trained = 0
    lookback = now - timedelta(hours=max(1, int(getattr(cfg, "proc_name_rarity_lookback_hours", 168))))
    min_samples = max(10, int(getattr(cfg, "if_training_min_samples", 500)))
    for agent_id in agents:
        latest = repository.get_latest_ml_model(
            db,
            detector_id=detector_id,
            agent_id=agent_id,
            model_type=model_type,
        )
        if latest is not None:
            finished = _as_utc(latest.training_finished_at)
            stale_after = timedelta(seconds=max(60, int(getattr(cfg, "if_model_stale_seconds", 86_400))))
            if latest.status == "active" and finished + stale_after > now:
                continue
        try:
            events = event_queries.fetch_proc_exec_events_for_agent(
                db,
                agent_id=agent_id,
                since=lookback,
                limit=max(min_samples, min_samples * 4),
            )
            if len(events) < min_samples:
                continue
            parent_vocab = ml.build_parent_vocab(events)
            matrix = _training_matrix(events, parent_vocab=parent_vocab)
            started_at = datetime.now(timezone.utc)
            trained_model = ml.train_isolation_forest(
                matrix,
                n_estimators=int(getattr(cfg, "if_n_estimators", 200)),
                random_state=int(getattr(cfg, "if_random_state", 42)),
                feature_schema_version=int(getattr(cfg, "if_feature_schema_version", ml.PROC_FEATURE_SCHEMA_VERSION)),
                parent_vocab=parent_vocab,
                contamination=str(getattr(cfg, "if_contamination", "auto")),
            )
            finished_at = datetime.now(timezone.utc)
            repository.mark_active_ml_models_superseded(
                db,
                detector_id=detector_id,
                agent_id=agent_id,
                model_type=model_type,
            )
            repository.create_ml_model(
                db,
                model_key=f"{detector_id}::{agent_id}::{model_type}",
                model_type=model_type,
                agent_id=agent_id,
                detector_id=detector_id,
                status="active",
                serialized_model=trained_model.serialized_model,
                feature_schema_version=int(getattr(cfg, "if_feature_schema_version", ml.PROC_FEATURE_SCHEMA_VERSION)),
                training_sample_count=len(matrix),
                training_started_at=started_at,
                training_finished_at=finished_at,
                anomaly_threshold=trained_model.anomaly_threshold,
                metadata_json=trained_model.metadata,
            )
            training_latency_ms = int((finished_at - started_at).total_seconds() * 1000)
            log_event(
                logger,
                "info",
                "ueba_ml_model_trained",
                detector_id=detector_id,
                agent_id=agent_id,
                model_type=model_type,
                training_sample_count=len(matrix),
                training_latency_ms=training_latency_ms,
            )
            trained += 1
        except Exception as exc:
            log_event(
                logger,
                "warning",
                "ueba_ml_training_failed",
                detector_id=detector_id,
                agent_id=agent_id,
                model_type=model_type,
                error_type=type(exc).__name__,
                error_message=str(exc)[:512],
            )
    return trained


def _training_matrix(events: list[Any], *, parent_vocab: dict[str, int]) -> list[list[float]]:
    proc_counts: dict[str, int] = {}
    total_executions = len(events)
    vocab_size = len({str(getattr(event, "proc_name", "") or "") for event in events})
    matrix: list[list[float]] = []
    timestamps = [_as_utc(event.timestamp) for event in events]
    window_start_idx = 0
    for idx, event in enumerate(events):
        event_ts = timestamps[idx]
        while window_start_idx < idx and timestamps[window_start_idx] < event_ts - timedelta(minutes=5):
            window_start_idx += 1
        proc_name = str(getattr(event, "proc_name", "") or "")
        prior_count = proc_counts.get(proc_name, 0)
        rarity = ml.process_rarity_bits(prior_count, total_executions, vocab_size)
        feature = ml.build_proc_feature_vector(
            event,
            rarity_bits=rarity,
            rolling_exec_rate_5m=float(idx - window_start_idx + 1),
            parent_vocab=parent_vocab,
        )
        matrix.append(list(feature.values))
        proc_counts[proc_name] = prior_count + 1
    return matrix


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = ["run_ueba_maintenance", "train_stale_isolation_forest_models"]
