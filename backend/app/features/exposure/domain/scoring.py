from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.features.exposure.domain.constants import (
    LOW_CONFIDENCE_THRESHOLD,
    MAX_RELIABILITY_PENALTY,
    RC_ACTIVE_ALERT,
    RC_ATTACK_CHAIN_PROGRESSION,
    RC_BRUTE_FORCE_ACTIVITY,
    RC_CRITICAL_CVE,
    RC_EXPLOITABILITY_SIGNAL,
    RC_EXPOSED_SERVICE,
    RC_LATERAL_MOVEMENT_SIGNAL,
    RC_LOW_EVIDENCE_CONFIDENCE,
    RC_PERSISTENCE_SIGNAL,
    RC_SENSITIVE_FILE_CHANGE,
    RC_STALE_AGENT,
    RC_STALE_INVENTORY,
    RC_SUSPICIOUS_PROCESS,
    RC_VULNERABLE_PACKAGE,
    SCORE_WEIGHT_ACTIVE_THREAT,
    SCORE_WEIGHT_ASSET_CRITICALITY,
    SCORE_WEIGHT_ATTACK_CHAIN,
    SCORE_WEIGHT_EXPOSURE,
    SCORE_WEIGHT_PERSISTENCE,
    SCORE_WEIGHT_VULNERABILITY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from app.features.exposure.domain.normalization import (
    clamp_confidence,
    clamp_score,
    severity_from_score,
)
from app.features.exposure.domain.types import EvidenceRef, ScoreBreakdown


_CRITICALITY_MULTIPLIER: dict[str, float] = {
    "critical": 1.0,
    "high": 0.80,
    "medium": 0.60,
    "low": 0.40,
    "none": 0.20,
    "unknown": 0.50,
}

_SEVERITY_SCORE_MAP: dict[str, int] = {
    SEVERITY_CRITICAL: 95,
    SEVERITY_HIGH: 72,
    SEVERITY_MEDIUM: 50,
    SEVERITY_LOW: 28,
    SEVERITY_INFORMATIONAL: 10,
}


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v)) if v is not None else default
    except (TypeError, ValueError):
        return default


def _age_penalty(last_seen_at: datetime | None, *, stale_hours: int = 168) -> float:
    """Return a 0.0–1.0 staleness multiplier (1.0 = fully fresh, 0.0 = very stale)."""
    if last_seen_at is None:
        return 0.5
    now = datetime.now(tz=timezone.utc)
    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
    age_hours = (now - last_seen_at).total_seconds() / 3600.0
    if age_hours <= 24:
        return 1.0
    if age_hours <= stale_hours:
        return max(0.3, 1.0 - ((age_hours - 24) / (stale_hours - 24)) * 0.7)
    return 0.2


@dataclass
class ScoringInputs:
    """Aggregated signal counts fed into the scoring engine."""

    asset_key: str
    agent_id: str | None
    asset_last_seen_at: datetime | None
    asset_criticality: str

    # Vulnerability signals
    critical_vuln_count: int = 0
    high_vuln_count: int = 0
    medium_vuln_count: int = 0
    low_vuln_count: int = 0
    has_exploitability_signal: bool = False

    # Threat signals
    active_alert_count: int = 0
    brute_force_count: int = 0
    lateral_movement_count: int = 0
    suspicious_process_count: int = 0

    # Persistence signals
    sensitive_file_change_count: int = 0
    persistence_signal_count: int = 0

    # Attack chain
    open_attack_chain_count: int = 0
    max_attack_chain_score: int = 0

    # Exposure
    exposed_service_count: int = 0

    # Freshness
    stale_agent: bool = False
    stale_inventory: bool = False

    # Evidence quality
    evidence_refs: list[EvidenceRef] | None = None
    base_confidence: int = 50


def compute_vulnerability_score(inputs: ScoringInputs) -> int:
    score = 0.0
    score += inputs.critical_vuln_count * 30.0
    score += inputs.high_vuln_count * 18.0
    score += inputs.medium_vuln_count * 8.0
    score += inputs.low_vuln_count * 2.0
    if inputs.has_exploitability_signal:
        score += 20.0
    return clamp_score(score)


def compute_active_threat_score(inputs: ScoringInputs) -> int:
    score = 0.0
    score += min(inputs.active_alert_count, 5) * 15.0
    score += min(inputs.brute_force_count, 3) * 12.0
    score += min(inputs.lateral_movement_count, 3) * 20.0
    score += min(inputs.suspicious_process_count, 5) * 8.0
    return clamp_score(score)


def compute_persistence_score(inputs: ScoringInputs) -> int:
    score = 0.0
    score += min(inputs.sensitive_file_change_count, 5) * 14.0
    score += min(inputs.persistence_signal_count, 5) * 18.0
    return clamp_score(score)


def compute_attack_chain_score(inputs: ScoringInputs) -> int:
    if inputs.open_attack_chain_count == 0:
        return 0
    # Attack chain score drives directly into the component score
    chain_base = min(inputs.max_attack_chain_score, 100)
    count_bonus = min(inputs.open_attack_chain_count - 1, 4) * 8
    return clamp_score(chain_base + count_bonus)


def compute_exposure_score(inputs: ScoringInputs) -> int:
    score = min(inputs.exposed_service_count, 10) * 10.0
    return clamp_score(score)


def compute_asset_criticality_score(inputs: ScoringInputs) -> int:
    mult = _CRITICALITY_MULTIPLIER.get(str(inputs.asset_criticality or "").lower(), 0.5)
    return clamp_score(mult * 100)


def compute_reliability_penalty(inputs: ScoringInputs) -> int:
    """
    Penalty deducted when evidence quality is degraded by age or low count.
    Bounded by MAX_RELIABILITY_PENALTY to prevent over-discounting.
    """
    penalty = 0
    last_seen = inputs.asset_last_seen_at
    if last_seen is not None:
        age_mult = _age_penalty(last_seen)
        if age_mult < 0.5:
            penalty += int((1.0 - age_mult) * 10)
    if inputs.stale_agent:
        penalty += 5
    if inputs.stale_inventory:
        penalty += 4
    ref_count = len(inputs.evidence_refs) if inputs.evidence_refs else 0
    if ref_count == 0:
        penalty += 5
    return min(penalty, MAX_RELIABILITY_PENALTY)


def compute_risk_score(
    inputs: ScoringInputs,
) -> tuple[int, ScoreBreakdown, int, list[str]]:
    """
    Return (risk_score, breakdown, confidence, reason_codes).
    All component scores are 0-100; the final score is the weighted sum clamped to 0-100.
    """
    vuln = compute_vulnerability_score(inputs)
    threat = compute_active_threat_score(inputs)
    persistence = compute_persistence_score(inputs)
    chain = compute_attack_chain_score(inputs)
    exposure = compute_exposure_score(inputs)
    criticality = compute_asset_criticality_score(inputs)
    penalty = compute_reliability_penalty(inputs)

    weighted = (
        vuln * SCORE_WEIGHT_VULNERABILITY
        + threat * SCORE_WEIGHT_ACTIVE_THREAT
        + persistence * SCORE_WEIGHT_PERSISTENCE
        + chain * SCORE_WEIGHT_ATTACK_CHAIN
        + exposure * SCORE_WEIGHT_EXPOSURE
        + criticality * SCORE_WEIGHT_ASSET_CRITICALITY
    )
    raw_score = clamp_score(weighted - penalty)

    breakdown = ScoreBreakdown(
        exposure_score=exposure,
        vulnerability_score=vuln,
        active_threat_score=threat,
        persistence_score=persistence,
        attack_chain_score=chain,
        asset_criticality_score=criticality,
        reliability_penalty=penalty,
    )

    reason_codes: list[str] = []
    if inputs.exposed_service_count > 0:
        reason_codes.append(RC_EXPOSED_SERVICE)
    if inputs.critical_vuln_count > 0:
        reason_codes.append(RC_CRITICAL_CVE)
    if inputs.critical_vuln_count > 0 or inputs.high_vuln_count > 0:
        reason_codes.append(RC_VULNERABLE_PACKAGE)
    if inputs.has_exploitability_signal:
        reason_codes.append(RC_EXPLOITABILITY_SIGNAL)
    if inputs.active_alert_count > 0:
        reason_codes.append(RC_ACTIVE_ALERT)
    if inputs.brute_force_count > 0:
        reason_codes.append(RC_BRUTE_FORCE_ACTIVITY)
    if inputs.lateral_movement_count > 0:
        reason_codes.append(RC_LATERAL_MOVEMENT_SIGNAL)
    if inputs.suspicious_process_count > 0:
        reason_codes.append(RC_SUSPICIOUS_PROCESS)
    if inputs.sensitive_file_change_count > 0:
        reason_codes.append(RC_SENSITIVE_FILE_CHANGE)
    if inputs.persistence_signal_count > 0:
        reason_codes.append(RC_PERSISTENCE_SIGNAL)
    if inputs.open_attack_chain_count > 0:
        reason_codes.append(RC_ATTACK_CHAIN_PROGRESSION)

    if inputs.stale_inventory:
        reason_codes.append(RC_STALE_INVENTORY)
    elif inputs.asset_last_seen_at is not None:
        age_mult = _age_penalty(inputs.asset_last_seen_at)
        if age_mult < 0.3:
            reason_codes.append(RC_STALE_INVENTORY)
    if inputs.stale_agent or inputs.agent_id is None:
        reason_codes.append(RC_STALE_AGENT)

    base_conf = clamp_confidence(inputs.base_confidence)
    if base_conf < LOW_CONFIDENCE_THRESHOLD:
        reason_codes.append(RC_LOW_EVIDENCE_CONFIDENCE)

    return raw_score, breakdown, base_conf, list(dict.fromkeys(reason_codes))
