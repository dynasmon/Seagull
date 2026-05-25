from __future__ import annotations

import math
from datetime import datetime, timezone
from types import SimpleNamespace

from app.features.ueba.config import FeedbackConfig
from app.features.ueba.domain import feedback, ml, peer_groups


def _feedback_cfg() -> FeedbackConfig:
    return FeedbackConfig(
        fp_confidence_factor=20.0,
        fp_decay=0.5,
        fp_sensitivity_step=0.4,
        tp_confidence_reinforce=12.0,
        tp_cooldown_scale=0.5,
        benign_confidence_factor=4.0,
        max_confidence_delta=40,
        max_sensitivity_scale=3.0,
        default_suppression_ttl_seconds=86_400,
    )


def test_feedback_projection_desensitizes_with_diminishing_returns() -> None:
    now = datetime(2026, 5, 25, 12, tzinfo=timezone.utc)
    state = feedback.BaselineFeedbackState()

    first = feedback.project_verdict(state, verdict=feedback.VERDICT_FALSE_POSITIVE, cfg=_feedback_cfg(), now=now)
    second = feedback.project_verdict(first, verdict=feedback.VERDICT_FALSE_POSITIVE, cfg=_feedback_cfg(), now=now)

    assert first.fp_count == 1
    assert first.confidence_delta == -20
    assert math.isclose(first.sensitivity_scale, 1.4)
    assert second.fp_count == 2
    assert second.confidence_delta == -30
    assert math.isclose(second.sensitivity_scale, 1.6)

    adjusted = feedback.apply_feedback_to_emission(
        confidence=80,
        risk_score=80,
        cooldown_minutes=60,
        state=second,
    )
    assert adjusted.confidence == 50
    assert adjusted.risk_score == 50
    assert adjusted.severity == "medium"
    assert adjusted.cooldown_minutes == 60
    assert adjusted.applied is True


def test_feedback_true_positive_reinforces_and_uses_one_shot_cooldown() -> None:
    now = datetime(2026, 5, 25, 12, tzinfo=timezone.utc)
    state = feedback.project_verdict(
        feedback.BaselineFeedbackState(confidence_delta=-10, sensitivity_scale=1.5),
        verdict=feedback.VERDICT_TRUE_POSITIVE,
        cfg=_feedback_cfg(),
        now=now,
    )

    adjusted = feedback.apply_feedback_to_emission(
        confidence=60,
        risk_score=75,
        cooldown_minutes=40,
        state=state,
    )
    assert state.tp_count == 1
    assert state.confidence_delta == 2
    assert adjusted.cooldown_minutes == 20
    assert adjusted.cooldown_oneshot_consumed is True
    assert feedback.verdict_conflict("true_positive", "false_positive") is True
    assert feedback.resolve_suppression(ttl_seconds=0, now=now).create is False
    assert feedback.resolve_suppression(ttl_seconds=None, now=now).permanent is True


def test_proc_feature_vector_is_fixed_width_and_finite_for_boundary_values() -> None:
    event = SimpleNamespace(
        timestamp=datetime(2026, 5, 25, 23, 30, tzinfo=timezone.utc),
        proc_parent_name="bash",
        proc_exe="/usr/bin/curl",
        effective_uid="not-an-int",
        proc_name="curl",
    )

    vector = ml.build_proc_feature_vector(
        event,
        rarity_bits=float("nan"),
        rolling_exec_rate_5m=float("inf"),
        parent_vocab={"bash": 7},
    )

    assert vector.names == ml.PROC_FEATURE_NAMES
    assert len(vector.values) == len(ml.PROC_FEATURE_NAMES)
    assert all(math.isfinite(value) for value in vector.values)
    assert vector.audit["parent_ordinal"] == 7.0
    assert vector.audit["uid_bucket"] == 3.0
    assert vector.audit["standard_system_path"] == 1.0
    assert vector.audit["shell_parent"] == 1.0


def test_isolation_forest_score_blends_or_falls_back_to_rarity() -> None:
    vector = ml.ProcFeatureVector(names=ml.PROC_FEATURE_NAMES, values=(0.0,) * len(ml.PROC_FEATURE_NAMES), audit={})

    fallback = ml.score_with_optional_model(
        model=None,
        feature_vector=vector,
        rarity_bits=3.0,
        if_weight=0.6,
        rarity_weight=0.4,
    )
    assert fallback.scoring_method == "frequency_rarity"
    assert fallback.deviation_score == 3.0

    class FakeModel:
        def decision_function(self, _matrix):
            return [-0.5]

    blended = ml.score_with_optional_model(
        model=FakeModel(),
        feature_vector=vector,
        rarity_bits=3.0,
        if_weight=0.6,
        rarity_weight=0.4,
    )
    assert blended.scoring_method == "isolation_forest_blended"
    assert blended.if_decision_score == -0.5
    assert blended.if_anomaly_component == 5.0
    assert math.isclose(blended.deviation_score, 4.2)


def test_peer_group_distance_and_percentiles_handle_empty_singleton_and_nan() -> None:
    assert peer_groups.percentile([], 95) is None
    assert peer_groups.percentile([7.0], 95) == 7.0
    assert peer_groups.percentile([0.0, 10.0], 50) == 5.0

    vector = {name: 0.0 for name in peer_groups.PEER_FEATURE_NAMES}
    vector["proc_exec_rate_mean"] = float("nan")
    centroid = {name: 0.0 for name in peer_groups.PEER_FEATURE_NAMES}
    covariance = {name: 1.0 for name in peer_groups.PEER_FEATURE_NAMES}
    assert peer_groups.mahalanobis_distance(vector, centroid=centroid, covariance=covariance) == 0.0

    normalized = peer_groups.normalize_fingerprints([])
    assert normalized.vectors == {}
    sparse_assignments = peer_groups.choose_peer_assignments(
        {"agent-1": centroid},
        min_silhouette_score=0.25,
        min_agents=2,
    )
    assert sparse_assignments[0].scoring_enabled is False
