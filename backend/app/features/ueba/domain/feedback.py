"""Pure analyst-feedback projection logic for the UEBA feedback loop.

Everything here is side-effect free and DB-free so it can be unit tested directly.
The service layer maps these results onto durable rows (``ueba_feedback``,
``ueba_suppressions``) and baseline columns; the detector chokepoint
(``support._record_finding``) consumes :func:`apply_feedback_to_emission`.

Verdict semantics
-----------------
* ``false_positive`` — desensitize the entity/detector pair (Surface A) and,
  unless ``suppression_ttl_seconds == 0``, open a suppression window (Surface B).
  The adjustment magnitude decays with the number of prior FP verdicts so the
  system grows increasingly skeptical of further auto-adjustments.
* ``true_positive`` — reinforce baseline confidence upward and halve the finding
  cooldown for the entity on the next cycle.
* ``benign_acknowledged`` — mild de-prioritization; acknowledged and closed, no
  suppression and no FP-style desensitization.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from app.features.ueba.config import FeedbackConfig
from app.features.ueba.domain.statistics import clamp_int, finite_float, severity_from_risk

VERDICT_TRUE_POSITIVE = "true_positive"
VERDICT_FALSE_POSITIVE = "false_positive"
VERDICT_BENIGN = "benign_acknowledged"
VERDICTS: tuple[str, ...] = (VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE, VERDICT_BENIGN)

_CONFLICTING_PAIRS = frozenset(
    {
        (VERDICT_TRUE_POSITIVE, VERDICT_FALSE_POSITIVE),
        (VERDICT_FALSE_POSITIVE, VERDICT_TRUE_POSITIVE),
    }
)


# --------------------------------------------------------------------------- #
# Baseline feedback state
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BaselineFeedbackState:
    fp_count: int = 0
    tp_count: int = 0
    confidence_delta: int = 0
    sensitivity_scale: float = 1.0
    cooldown_scale: float = 1.0
    last_verdict: str | None = None
    last_annotated_at: datetime | None = None


def feedback_state_from_baseline(baseline: object) -> BaselineFeedbackState:
    return BaselineFeedbackState(
        fp_count=max(0, int(getattr(baseline, "feedback_fp_count", 0) or 0)),
        tp_count=max(0, int(getattr(baseline, "feedback_tp_count", 0) or 0)),
        confidence_delta=int(getattr(baseline, "feedback_confidence_delta", 0) or 0),
        sensitivity_scale=max(1.0, finite_float(getattr(baseline, "feedback_sensitivity_scale", 1.0), default=1.0)),
        cooldown_scale=max(0.0, finite_float(getattr(baseline, "feedback_cooldown_scale", 1.0), default=1.0)),
        last_verdict=(getattr(baseline, "feedback_last_verdict", None) or None),
        last_annotated_at=getattr(baseline, "feedback_last_annotated_at", None),
    )


def baseline_feedback_updates(state: BaselineFeedbackState) -> dict:
    return {
        "feedback_fp_count": int(state.fp_count),
        "feedback_tp_count": int(state.tp_count),
        "feedback_confidence_delta": int(state.confidence_delta),
        "feedback_sensitivity_scale": float(state.sensitivity_scale),
        "feedback_cooldown_scale": float(state.cooldown_scale),
        "feedback_last_verdict": state.last_verdict,
        "feedback_last_annotated_at": state.last_annotated_at,
    }


def decayed_increment(base: float, prior_count: int, decay: float) -> float:
    base_v = max(0.0, finite_float(base, default=0.0))
    decay_v = min(1.0, max(0.0, finite_float(decay, default=0.0)))
    prior = max(0, int(prior_count))
    return finite_float(base_v * (decay_v**prior), default=0.0)


def project_verdict(
    state: BaselineFeedbackState,
    *,
    verdict: str,
    cfg: FeedbackConfig,
    now: datetime,
) -> BaselineFeedbackState:
    if verdict == VERDICT_FALSE_POSITIVE:
        inc_conf = decayed_increment(cfg.fp_confidence_factor, state.fp_count, cfg.fp_decay)
        inc_sens = decayed_increment(cfg.fp_sensitivity_step, state.fp_count, cfg.fp_decay)
        new_delta = clamp_int(
            state.confidence_delta - round(inc_conf),
            lo=-int(cfg.max_confidence_delta),
            hi=int(cfg.max_confidence_delta),
        )
        new_scale = min(float(cfg.max_sensitivity_scale), max(1.0, state.sensitivity_scale + inc_sens))
        return replace(
            state,
            fp_count=state.fp_count + 1,
            confidence_delta=new_delta,
            sensitivity_scale=new_scale,
            last_verdict=verdict,
            last_annotated_at=now,
        )

    if verdict == VERDICT_TRUE_POSITIVE:
        new_delta = clamp_int(
            state.confidence_delta + round(cfg.tp_confidence_reinforce),
            lo=-int(cfg.max_confidence_delta),
            hi=int(cfg.max_confidence_delta),
        )
        return replace(
            state,
            tp_count=state.tp_count + 1,
            confidence_delta=new_delta,
            cooldown_scale=min(1.0, max(0.0, float(cfg.tp_cooldown_scale))),
            last_verdict=verdict,
            last_annotated_at=now,
        )

    if verdict == VERDICT_BENIGN:
        new_delta = clamp_int(
            state.confidence_delta - round(cfg.benign_confidence_factor),
            lo=-int(cfg.max_confidence_delta),
            hi=int(cfg.max_confidence_delta),
        )
        return replace(
            state,
            confidence_delta=new_delta,
            last_verdict=verdict,
            last_annotated_at=now,
        )

    raise ValueError(f"unknown verdict: {verdict!r}")


@dataclass(frozen=True)
class EmissionAdjustment:
    confidence: int
    risk_score: int
    severity: str
    cooldown_minutes: int
    cooldown_oneshot_consumed: bool
    applied: bool


def apply_feedback_to_emission(
    *,
    confidence: int,
    risk_score: int,
    cooldown_minutes: int,
    state: BaselineFeedbackState,
) -> EmissionAdjustment:
    base_cd = max(1, int(cooldown_minutes))
    eff_conf = clamp_int(int(confidence) + int(state.confidence_delta), lo=0, hi=100)
    scale = max(1.0, finite_float(state.sensitivity_scale, default=1.0))
    eff_risk = clamp_int(round(finite_float(risk_score, default=0.0) / scale), lo=0, hi=100)
    eff_sev = severity_from_risk(eff_risk)
    cooldown_scale = finite_float(state.cooldown_scale, default=1.0)
    oneshot = cooldown_scale < 1.0
    eff_cd = max(1, int(round(base_cd * cooldown_scale))) if oneshot else base_cd
    applied = bool(int(state.confidence_delta) != 0 or scale > 1.0 or oneshot)
    return EmissionAdjustment(
        confidence=eff_conf,
        risk_score=eff_risk,
        severity=eff_sev,
        cooldown_minutes=eff_cd,
        cooldown_oneshot_consumed=oneshot,
        applied=applied,
    )


def verdict_conflict(prior_verdict: str | None, incoming_verdict: str) -> bool:
    if not prior_verdict:
        return False
    return (str(prior_verdict), str(incoming_verdict)) in _CONFLICTING_PAIRS


def suppression_scope_key(
    detector_id: str,
    agent_id: str | None,
    entity_type: str,
    entity_value: str,
) -> str:
    raw = "|".join([str(detector_id or ""), str(agent_id or ""), str(entity_type or ""), str(entity_value or "")])
    return "s:" + hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:40]


@dataclass(frozen=True)
class SuppressionPlan:
    create: bool
    permanent: bool
    expires_at: datetime | None


def resolve_suppression(*, ttl_seconds: int | None, now: datetime) -> SuppressionPlan:
    if ttl_seconds is None:
        return SuppressionPlan(create=True, permanent=True, expires_at=None)
    ttl = int(ttl_seconds)
    if ttl <= 0:
        return SuppressionPlan(create=False, permanent=False, expires_at=None)
    return SuppressionPlan(create=True, permanent=False, expires_at=now + timedelta(seconds=ttl))


def default_status_for_verdict(verdict: str, *, suppression_created: bool) -> str:
    if verdict == VERDICT_FALSE_POSITIVE:
        return "suppressed" if suppression_created else "closed"
    if verdict == VERDICT_BENIGN:
        return "closed"
    return "open"


__all__ = [
    "BaselineFeedbackState",
    "EmissionAdjustment",
    "SuppressionPlan",
    "VERDICTS",
    "VERDICT_BENIGN",
    "VERDICT_FALSE_POSITIVE",
    "VERDICT_TRUE_POSITIVE",
    "apply_feedback_to_emission",
    "baseline_feedback_updates",
    "decayed_increment",
    "default_status_for_verdict",
    "feedback_state_from_baseline",
    "project_verdict",
    "resolve_suppression",
    "suppression_scope_key",
    "verdict_conflict",
]
