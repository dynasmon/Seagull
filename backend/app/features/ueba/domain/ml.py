"""UEBA ML feature extraction and scoring helpers."""

from __future__ import annotations

import io
import math
import pickle
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from app.features.ueba.domain.statistics import finite_float

MODEL_TYPE_ISOLATION_FOREST = "isolation_forest"
PROC_FEATURE_SCHEMA_VERSION = 1

PROC_FEATURE_NAMES: tuple[str, ...] = (
    "hour_sin",
    "hour_cos",
    "parent_ordinal",
    "process_rarity_bits",
    "uid_bucket",
    "standard_system_path",
    "shell_parent",
    "exec_rate_5m",
)

STANDARD_SYSTEM_DIRS: tuple[str, ...] = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/lib/systemd/",
)
SHELL_PARENTS: frozenset[str] = frozenset({"bash", "sh", "zsh", "fish", "dash", "ksh", "python", "python3"})


@dataclass(frozen=True)
class ProcFeatureVector:
    names: tuple[str, ...]
    values: tuple[float, ...]
    audit: dict[str, Any]


@dataclass(frozen=True)
class MlScore:
    scoring_method: str
    deviation_score: float
    if_decision_score: float | None
    if_anomaly_component: float | None
    rarity_bits: float
    explanation: dict[str, Any]
    fallback_reason: str | None = None


@dataclass(frozen=True)
class TrainedIsolationForest:
    serialized_model: bytes
    anomaly_threshold: float
    metadata: dict[str, Any]


def process_rarity_bits(observation_count: int, total_executions: int, vocab_size: int) -> float:
    probability = (max(0, int(observation_count)) + 1) / (
        max(0, int(total_executions)) + max(0, int(vocab_size)) + 1
    )
    return finite_float(-math.log2(max(probability, 1e-9)))


def build_parent_vocab(events: Iterable[Any], *, cap: int = 256) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for event in events:
        parent = str(getattr(event, "proc_parent_name", "") or "").strip().lower()
        if parent:
            counts[parent] += 1
    return {name: idx for idx, (name, _count) in enumerate(counts.most_common(max(1, int(cap))))}


def build_proc_feature_vector(
    event: Any,
    *,
    rarity_bits: float,
    rolling_exec_rate_5m: float,
    parent_vocab: dict[str, int] | None = None,
    parent_vocab_cap: int = 256,
) -> ProcFeatureVector:
    ts = _coerce_dt(getattr(event, "timestamp", None))
    hour = float(ts.hour + (ts.minute / 60.0) + (ts.second / 3600.0))
    radians = (hour / 24.0) * math.tau
    parent = str(getattr(event, "proc_parent_name", "") or "").strip().lower()
    parent_code = float((parent_vocab or {}).get(parent, max(1, int(parent_vocab_cap))))
    exe = str(getattr(event, "proc_exe", "") or "")
    effective_uid = getattr(event, "effective_uid", None)
    uid_bucket = float(_uid_bucket(effective_uid))
    standard_path = 1.0 if _is_standard_system_path(exe) else 0.0
    shell_parent = 1.0 if parent in SHELL_PARENTS else 0.0
    values = (
        finite_float(math.sin(radians)),
        finite_float(math.cos(radians)),
        finite_float(parent_code),
        finite_float(rarity_bits),
        uid_bucket,
        standard_path,
        shell_parent,
        finite_float(rolling_exec_rate_5m),
    )
    audit = {
        name: value
        for name, value in zip(PROC_FEATURE_NAMES, values, strict=True)
    }
    audit.update(
        {
            "hour": round(hour, 4),
            "proc_name": str(getattr(event, "proc_name", "") or ""),
            "proc_exe": exe or None,
            "proc_parent_name": parent or None,
            "effective_uid": effective_uid,
        }
    )
    return ProcFeatureVector(names=PROC_FEATURE_NAMES, values=values, audit=audit)


def score_with_optional_model(
    *,
    model: Any | None,
    feature_vector: ProcFeatureVector,
    rarity_bits: float,
    if_weight: float,
    rarity_weight: float,
    fallback_reason: str | None = None,
) -> MlScore:
    rarity = finite_float(rarity_bits)
    if model is None:
        return MlScore(
            scoring_method="frequency_rarity",
            deviation_score=rarity,
            if_decision_score=None,
            if_anomaly_component=None,
            rarity_bits=rarity,
            fallback_reason=fallback_reason or "model_unavailable",
            explanation={
                "scoring_method": "frequency_rarity",
                "rarity_bits": rarity,
                "fallback_reason": fallback_reason or "model_unavailable",
                "feature_vector": feature_vector.audit,
            },
        )
    try:
        raw_decision = float(model.decision_function([list(feature_vector.values)])[0])
    except Exception as exc:
        return score_with_optional_model(
            model=None,
            feature_vector=feature_vector,
            rarity_bits=rarity,
            if_weight=if_weight,
            rarity_weight=rarity_weight,
            fallback_reason=f"model_score_failed:{type(exc).__name__}",
        )
    if_component = finite_float(max(0.0, -raw_decision) * 10.0)
    iw = min(1.0, max(0.0, finite_float(if_weight, default=0.6)))
    rw = min(1.0, max(0.0, finite_float(rarity_weight, default=0.4)))
    total = iw + rw
    if total <= 0:
        iw, rw, total = 0.6, 0.4, 1.0
    blended = finite_float(((if_component * iw) + (rarity * rw)) / total)
    return MlScore(
        scoring_method="isolation_forest_blended",
        deviation_score=blended,
        if_decision_score=raw_decision,
        if_anomaly_component=if_component,
        rarity_bits=rarity,
        explanation={
            "scoring_method": "isolation_forest_blended",
            "if_decision_score": raw_decision,
            "if_anomaly_component": if_component,
            "rarity_bits": rarity,
            "blend_weights": {"isolation_forest": iw, "rarity": rw},
            "feature_schema_version": PROC_FEATURE_SCHEMA_VERSION,
            "feature_vector": feature_vector.audit,
        },
    )


def train_isolation_forest(
    matrix: list[list[float]],
    *,
    n_estimators: int,
    random_state: int,
    feature_schema_version: int,
    parent_vocab: dict[str, int],
    contamination: str = "auto",
) -> TrainedIsolationForest:
    if len(matrix) < 2:
        raise ValueError("isolation forest training requires at least two samples")
    try:
        from sklearn.ensemble import IsolationForest
    except Exception as exc:  # pragma: no cover - depends on optional runtime package
        raise RuntimeError("scikit-learn is required for IsolationForest training") from exc

    contamination_val: object = "auto"
    if str(contamination) != "auto":
        try:
            contamination_val = float(contamination)
        except (TypeError, ValueError):
            contamination_val = "auto"

    model = IsolationForest(
        contamination=contamination_val,
        n_estimators=max(10, int(n_estimators)),
        random_state=int(random_state),
    )
    model.fit(matrix)
    decisions = [float(v) for v in model.decision_function(matrix)]
    payload = serialize_model(model)
    return TrainedIsolationForest(
        serialized_model=payload,
        anomaly_threshold=0.0,
        metadata={
            "feature_names": list(PROC_FEATURE_NAMES),
            "feature_schema_version": int(feature_schema_version),
            "parent_vocab": parent_vocab,
            "decision_score_min": min(decisions) if decisions else None,
            "decision_score_max": max(decisions) if decisions else None,
            "decision_score_mean": (sum(decisions) / len(decisions)) if decisions else None,
        },
    )


def serialize_model(model: Any) -> bytes:
    try:
        import joblib

        buffer = io.BytesIO()
        joblib.dump(model, buffer)
        return buffer.getvalue()
    except Exception:
        return pickle.dumps(model)


def deserialize_model(payload: bytes) -> Any:
    data = bytes(payload or b"")
    if not data:
        return None
    try:
        import joblib

        return joblib.load(io.BytesIO(data))
    except Exception:
        return pickle.loads(data)


def _uid_bucket(value: Any) -> int:
    try:
        uid = int(value)
    except (TypeError, ValueError):
        return 3
    if uid == 0:
        return 0
    if 1 <= uid <= 999:
        return 1
    return 2


def _is_standard_system_path(path: str) -> bool:
    clean = str(path or "").strip()
    return bool(clean and any(clean.startswith(prefix) for prefix in STANDARD_SYSTEM_DIRS))


def _coerce_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.utcnow()


__all__ = [
    "MODEL_TYPE_ISOLATION_FOREST",
    "PROC_FEATURE_NAMES",
    "PROC_FEATURE_SCHEMA_VERSION",
    "MlScore",
    "ProcFeatureVector",
    "TrainedIsolationForest",
    "build_parent_vocab",
    "build_proc_feature_vector",
    "deserialize_model",
    "process_rarity_bits",
    "score_with_optional_model",
    "serialize_model",
    "train_isolation_forest",
]
