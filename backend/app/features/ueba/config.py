from __future__ import annotations

from dataclasses import dataclass

from app.core.config.env_secrets import env_value


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
class FeedbackConfig:
    fp_confidence_factor: float
    fp_decay: float
    fp_sensitivity_step: float
    tp_confidence_reinforce: float
    tp_cooldown_scale: float
    benign_confidence_factor: float
    max_confidence_delta: int
    max_sensitivity_scale: float
    default_suppression_ttl_seconds: int


@dataclass(frozen=True)
class MlConfig:
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


@dataclass(frozen=True)
class PeerGroupConfig:
    clustering_interval_seconds: int
    retention_days: int
    min_silhouette_score: float
    distance_percentile: float
    current_window_minutes: int
    feature_schema_version: int
    min_agents: int
    min_mature_days: int
    max_events_per_clustering: int


def load_feedback_config() -> FeedbackConfig:
    return FeedbackConfig(
        fp_confidence_factor=max(0.0, _env_float("SEAGULL_UEBA_FEEDBACK_FP_CONFIDENCE_FACTOR", 15.0)),
        fp_decay=min(1.0, max(0.0, _env_float("SEAGULL_UEBA_FEEDBACK_FP_DECAY", 0.6))),
        fp_sensitivity_step=max(0.0, _env_float("SEAGULL_UEBA_FEEDBACK_FP_SENSITIVITY_STEP", 0.5)),
        tp_confidence_reinforce=max(0.0, _env_float("SEAGULL_UEBA_FEEDBACK_TP_CONFIDENCE_REINFORCE", 10.0)),
        tp_cooldown_scale=min(1.0, max(0.0, _env_float("SEAGULL_UEBA_FEEDBACK_TP_COOLDOWN_SCALE", 0.5))),
        benign_confidence_factor=max(0.0, _env_float("SEAGULL_UEBA_FEEDBACK_BENIGN_CONFIDENCE_FACTOR", 5.0)),
        max_confidence_delta=max(0, _env_int("SEAGULL_UEBA_FEEDBACK_MAX_CONFIDENCE_DELTA", 60)),
        max_sensitivity_scale=max(1.0, _env_float("SEAGULL_UEBA_FEEDBACK_MAX_SENSITIVITY_SCALE", 8.0)),
        default_suppression_ttl_seconds=max(
            0,
            _env_int("SEAGULL_UEBA_FEEDBACK_DEFAULT_SUPPRESSION_TTL_SECONDS", 86_400),
        ),
    )


def load_ml_config() -> MlConfig:
    if_weight = min(1.0, max(0.0, _env_float("SEAGULL_UEBA_IF_BLEND_WEIGHT", 0.6)))
    return MlConfig(
        if_training_min_samples=max(10, _env_int("SEAGULL_UEBA_IF_TRAINING_MIN_SAMPLES", 500)),
        if_retraining_interval_seconds=max(60, _env_int("SEAGULL_UEBA_IF_RETRAINING_INTERVAL_SECONDS", 21_600)),
        if_model_stale_seconds=max(60, _env_int("SEAGULL_UEBA_IF_MODEL_STALE_SECONDS", 86_400)),
        if_model_retention_days=max(1, _env_int("SEAGULL_UEBA_IF_MODEL_RETENTION_DAYS", 30)),
        if_model_cache_ttl_seconds=max(1, _env_int("SEAGULL_UEBA_IF_MODEL_CACHE_TTL_SECONDS", 300)),
        if_weight=if_weight,
        rarity_weight=min(1.0, max(0.0, _env_float("SEAGULL_UEBA_RARITY_BLEND_WEIGHT", 1.0 - if_weight))),
        if_n_estimators=max(10, _env_int("SEAGULL_UEBA_IF_N_ESTIMATORS", 200)),
        if_random_state=_env_int("SEAGULL_UEBA_IF_RANDOM_STATE", 42),
        if_feature_schema_version=max(1, _env_int("SEAGULL_UEBA_IF_FEATURE_SCHEMA_VERSION", 1)),
    )


def load_peer_group_config() -> PeerGroupConfig:
    return PeerGroupConfig(
        clustering_interval_seconds=max(60, _env_int("SEAGULL_UEBA_PEER_CLUSTERING_INTERVAL_SECONDS", 21_600)),
        retention_days=max(1, _env_int("SEAGULL_UEBA_PEER_GROUP_RETENTION_DAYS", 90)),
        min_silhouette_score=max(0.0, _env_float("SEAGULL_UEBA_PEER_MIN_SILHOUETTE_SCORE", 0.25)),
        distance_percentile=min(99.9, max(50.0, _env_float("SEAGULL_UEBA_PEER_DISTANCE_PERCENTILE", 95.0))),
        current_window_minutes=max(5, _env_int("SEAGULL_UEBA_PEER_CURRENT_WINDOW_MINUTES", 60)),
        feature_schema_version=max(1, _env_int("SEAGULL_UEBA_PEER_FEATURE_SCHEMA_VERSION", 1)),
        min_agents=max(2, _env_int("SEAGULL_UEBA_PEER_MIN_AGENTS", 4)),
        min_mature_days=max(0, _env_int("SEAGULL_UEBA_PEER_MIN_MATURE_DAYS", 3)),
        max_events_per_clustering=max(1000, _env_int("SEAGULL_UEBA_PEER_MAX_EVENTS_PER_CLUSTERING", 50_000)),
    )


__all__ = [
    "FeedbackConfig",
    "MlConfig",
    "PeerGroupConfig",
    "load_feedback_config",
    "load_ml_config",
    "load_peer_group_config",
]
