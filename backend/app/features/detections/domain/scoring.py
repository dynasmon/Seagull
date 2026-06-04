"""Deterministic per-alert risk- and confidence-scoring primitives.

Single source of truth for the severity -> baseline mappings shared by alert
creation (the rule engine and the v2 compiler) and correlation risk aggregation,
plus an explainable contextual scorer.

The scorer takes a declared base (the rule's ``risk_score`` or the severity
baseline) and applies bounded, documented adjustments from signals the caller
passes in -- event volume vs threshold, source/destination locality, evidence
richness, ATT&CK mapping, maturity, and false-positive-close feedback. It emits
an ordered, JSON-serializable ``score_breakdown`` where every factor records its
own risk and confidence delta, so an operator can read exactly why an alert
scored the way it did. No I/O lives here: signals are supplied by the caller, so
the scorer stays pure and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from app.shared.network.ip_classification import classify_ip

_SEVERITY_RISK_BASELINE: dict[str, int] = {
    "critical": 95,
    "high": 78,
    "medium": 52,
    "low": 30,
    "info": 12,
}
_DEFAULT_RISK_BASELINE = 40

_SEVERITY_CONFIDENCE_BASELINE: dict[str, int] = {
    "critical": 80,
    "high": 70,
    "medium": 55,
    "low": 40,
    "info": 30,
}
_DEFAULT_CONFIDENCE_BASELINE = 50

_LOCAL_ONLY_SCOPES = frozenset({"loopback", "link_local", "unspecified", "invalid"})
_EXPERIMENTAL_MATURITIES = frozenset({"draft", "experimental"})
_FP_FEEDBACK_MIN_SAMPLES = 5


def clamp_score(value: Any) -> int:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, number))


def severity_baseline_score(severity: Any) -> int:
    return _SEVERITY_RISK_BASELINE.get(str(severity or "").strip().lower(), _DEFAULT_RISK_BASELINE)


def severity_confidence_baseline(severity: Any) -> int:
    return _SEVERITY_CONFIDENCE_BASELINE.get(str(severity or "").strip().lower(), _DEFAULT_CONFIDENCE_BASELINE)


def resolve_alert_risk_score(rule: Mapping[str, Any], effective_severity: Any) -> int:
    """Effective per-alert *base* risk: the rule's declared ``risk_score`` when
    present, otherwise the severity baseline. Always clamped to 0-100. Kept as the
    deterministic base that :func:`score_alert` builds on."""
    declared = rule.get("risk_score") if isinstance(rule, Mapping) else None
    if declared is not None:
        return clamp_score(declared)
    return severity_baseline_score(effective_severity)


def build_rule_provenance(rule: Mapping[str, Any]) -> dict[str, Any]:
    """Provenance block stored under ``details['rule_meta']`` for every rule alert."""
    return {
        "pack": rule.get("pack"),
        "category": rule.get("category"),
        "rule_version": int(rule.get("rule_version") or 1),
        "maturity": rule.get("maturity"),
        "risk_score": rule.get("risk_score"),
    }


@dataclass(frozen=True)
class ScoreSignals:
    """Explicit, I/O-free inputs to :func:`score_alert`. The caller resolves each
    signal from the rule, the alert context, and (for FP feedback) a batched
    read-only aggregate."""

    severity: str
    declared_risk_score: int | None = None
    rule_confidence: int | None = None
    maturity: str | None = None
    event_count: int | None = None
    distinct_count: int | None = None
    threshold: int | None = None
    src_scope: str | None = None
    dst_scope: str | None = None
    src_is_public: bool = False
    dst_is_internal: bool = False
    has_mitre: bool = False
    evidence_field_count: int = 0
    fp_close_rate: float | None = None
    fp_close_samples: int = 0
    correlated: bool = False


@dataclass
class ScoreResult:
    risk_score: int
    confidence: int
    breakdown: list[dict[str, Any]]


def _factor(name: str, risk_delta: int, confidence_delta: int, detail: str) -> dict[str, Any]:
    return {
        "factor": name,
        "risk_delta": int(risk_delta),
        "confidence_delta": int(confidence_delta),
        "detail": detail,
    }


def score_alert(signals: ScoreSignals) -> ScoreResult:
    """Deterministic, explainable contextual score. Returns the final risk and
    confidence plus an ordered breakdown; ``risk_score`` and ``confidence`` are the
    clamped sums of the per-factor deltas, the first of which is the base."""
    sev = str(signals.severity or "").strip().lower()

    if signals.declared_risk_score is not None:
        base_risk = clamp_score(signals.declared_risk_score)
        base_detail = f"declared risk_score {base_risk}"
    else:
        base_risk = severity_baseline_score(sev)
        base_detail = f"severity '{sev or 'unknown'}' baseline"

    if signals.rule_confidence is not None:
        base_conf = max(0, min(100, int(signals.rule_confidence)))
    else:
        base_conf = severity_confidence_baseline(sev)

    factors: list[dict[str, Any]] = [_factor("base", base_risk, base_conf, base_detail)]

    volume = max(int(signals.event_count or 0), int(signals.distinct_count or 0))
    threshold = signals.threshold if (signals.threshold and signals.threshold > 0) else 1
    if volume > 0:
        ratio = volume / threshold
        if ratio >= 3:
            factors.append(_factor("aggregation_strength", 6, 3, f"{volume} >= 3x threshold ({threshold})"))
        elif ratio >= 1.5:
            factors.append(_factor("aggregation_strength", 3, 2, f"{volume} >= 1.5x threshold ({threshold})"))

    if signals.src_is_public and signals.dst_is_internal:
        factors.append(_factor("locality", 6, 4, "external source targeting an internal asset"))
    elif signals.src_scope in _LOCAL_ONLY_SCOPES and (
        signals.dst_scope in _LOCAL_ONLY_SCOPES or signals.dst_scope is None
    ):
        factors.append(_factor("locality", -8, -6, "loopback/local-only endpoints (likely test or noise)"))

    evidence_fields = int(signals.evidence_field_count or 0)
    if evidence_fields >= 4:
        factors.append(_factor("evidence_richness", 6, 5, f"rich evidence ({evidence_fields} entity/context fields)"))
    elif evidence_fields >= 2:
        factors.append(_factor("evidence_richness", 3, 2, f"moderate evidence ({evidence_fields} fields)"))
    elif evidence_fields <= 0:
        factors.append(_factor("evidence_richness", -4, -5, "sparse evidence (no strong entity fields)"))

    if signals.has_mitre:
        factors.append(_factor("mitre_mapping", 3, 4, "ATT&CK technique mapped"))
    else:
        factors.append(_factor("mitre_mapping", -2, -3, "no ATT&CK mapping"))

    maturity = str(signals.maturity or "").strip().lower()
    if maturity in _EXPERIMENTAL_MATURITIES:
        factors.append(_factor("maturity", -5, -5, f"{maturity} maturity (lower trust)"))
    elif maturity == "stable":
        factors.append(_factor("maturity", 2, 2, "stable maturity"))

    if signals.fp_close_rate is not None and signals.fp_close_samples >= _FP_FEEDBACK_MIN_SAMPLES:
        rate = float(signals.fp_close_rate)
        pct = int(round(rate * 100))
        samples = int(signals.fp_close_samples)
        if rate >= 0.7:
            factors.append(_factor("fp_feedback", -15, -12, f"{pct}% of recent closes were false positives ({samples} samples)"))
        elif rate >= 0.4:
            factors.append(_factor("fp_feedback", -8, -6, f"{pct}% recent false-positive closes ({samples} samples)"))
        elif rate <= 0.1:
            factors.append(_factor("fp_feedback", 3, 2, f"rarely closed as false positive ({pct}%, {samples} samples)"))

    if signals.correlated:
        factors.append(_factor("correlated", 5, 4, "part of a correlated pattern"))

    risk_score = clamp_score(sum(int(f["risk_delta"]) for f in factors))
    confidence = max(0, min(100, sum(int(f["confidence_delta"]) for f in factors)))
    return ScoreResult(risk_score=risk_score, confidence=confidence, breakdown=factors)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _rule_confidence(rule: Mapping[str, Any], details: Mapping[str, Any]) -> int | None:
    mitre = details.get("mitre") if isinstance(details, Mapping) else None
    candidates = ((mitre or {}).get("confidence") if isinstance(mitre, Mapping) else None, rule.get("confidence"))
    for candidate in candidates:
        resolved = _int_or_none(candidate)
        if resolved is not None:
            return resolved
    return None


def _distinct_from_details(details: Mapping[str, Any]) -> int | None:
    direct = _int_or_none(details.get("distinct_count"))
    if direct is not None:
        return direct
    distinct = details.get("distinct")
    if isinstance(distinct, Mapping) and distinct:
        values = [v for v in (_int_or_none(item) for item in distinct.values()) if v is not None]
        if values:
            return max(values)
    return None


def _threshold_from_details(rule: Mapping[str, Any], details: Mapping[str, Any]) -> int | None:
    tuning = details.get("tuning") if isinstance(details.get("tuning"), Mapping) else {}
    condition = rule.get("condition") if isinstance(rule.get("condition"), Mapping) else {}
    for candidate in (
        tuning.get("effective_min_events"),
        rule.get("min_events"),
        condition.get("value"),
        condition.get("min_events"),
    ):
        resolved = _int_or_none(candidate)
        if resolved:
            return resolved
    return None


def evidence_field_count(details: Mapping[str, Any]) -> int:
    """Count the strong entity/context evidence fields already captured in
    ``details`` (matched group entities, distinct cardinality, multi-source fan-in)."""
    group_key = details.get("group_key") if isinstance(details.get("group_key"), Mapping) else {}
    count = sum(1 for value in group_key.values() if value not in (None, "", "-"))
    if details.get("distinct_count") or details.get("distinct"):
        count += 1
    enrichment = details.get("enrichment") if isinstance(details.get("enrichment"), Mapping) else {}
    if int(_int_or_none(enrichment.get("unique_src_ips")) or 0) > 1:
        count += 1
    return count


def score_alert_from_details(
    rule: Mapping[str, Any],
    effective_severity: Any,
    details: Mapping[str, Any],
    *,
    src_scope: str | None = None,
    dst_scope: str | None = None,
    src_is_public: bool = False,
    dst_is_internal: bool = False,
    fp_close_rate: float | None = None,
    fp_close_samples: int = 0,
    correlated: bool = False,
) -> ScoreResult:
    """Thin, DRY adapter used by both the v1 engine and the v2 compiler: resolves
    :class:`ScoreSignals` from the already-built ``details`` dict plus caller-supplied
    locality / FP-feedback signals, then delegates to :func:`score_alert`."""
    declared = rule.get("risk_score")
    signals = ScoreSignals(
        severity=str(effective_severity or ""),
        declared_risk_score=_int_or_none(declared),
        rule_confidence=_rule_confidence(rule, details),
        maturity=rule.get("maturity"),
        event_count=_int_or_none(details.get("count")),
        distinct_count=_distinct_from_details(details),
        threshold=_threshold_from_details(rule, details),
        src_scope=src_scope,
        dst_scope=dst_scope,
        src_is_public=bool(src_is_public),
        dst_is_internal=bool(dst_is_internal),
        has_mitre=bool(details.get("mitre")),
        evidence_field_count=evidence_field_count(details),
        fp_close_rate=fp_close_rate,
        fp_close_samples=int(fp_close_samples or 0),
        correlated=bool(correlated),
    )
    return score_alert(signals)


def score_alert_for_endpoints(
    rule: Mapping[str, Any],
    rule_id: Any,
    effective_severity: Any,
    details: Mapping[str, Any],
    *,
    src_ip: Any = None,
    dst_ip: Any = None,
    fp_rates: Mapping[str, tuple] | None = None,
) -> ScoreResult:
    """Shared marshaling entry point for both the v1 engine and the v2 compiler:
    resolves source/destination locality via the canonical :func:`classify_ip`
    (pure) and the per-rule false-positive-close rate from the caller-supplied
    batched map, then delegates to :func:`score_alert_from_details`."""
    src = classify_ip(src_ip)
    dst = classify_ip(dst_ip)
    feedback = (fp_rates or {}).get(str(rule_id)) if rule_id is not None else None
    return score_alert_from_details(
        rule,
        effective_severity,
        details,
        src_scope=src["scope"],
        dst_scope=dst["scope"],
        src_is_public=bool(src["is_public"]),
        dst_is_internal=bool(dst["is_internal"]),
        fp_close_rate=feedback[0] if feedback else None,
        fp_close_samples=feedback[1] if feedback else 0,
    )


__all__ = [
    "clamp_score",
    "severity_baseline_score",
    "severity_confidence_baseline",
    "resolve_alert_risk_score",
    "build_rule_provenance",
    "ScoreSignals",
    "ScoreResult",
    "score_alert",
    "score_alert_from_details",
    "score_alert_for_endpoints",
    "evidence_field_count",
]
