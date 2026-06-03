from __future__ import annotations

from typing import Any, Mapping

_SEVERITY_RISK_BASELINE: dict[str, int] = {
    "critical": 95,
    "high": 78,
    "medium": 52,
    "low": 30,
    "info": 12,
}
_DEFAULT_RISK_BASELINE = 40


def clamp_score(value: Any) -> int:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(100, number))


def severity_baseline_score(severity: Any) -> int:
    return _SEVERITY_RISK_BASELINE.get(str(severity or "").strip().lower(), _DEFAULT_RISK_BASELINE)


def resolve_alert_risk_score(rule: Mapping[str, Any], effective_severity: Any) -> int:
    """Effective per-alert risk: the rule's declared ``risk_score`` when present,
    otherwise the severity baseline. Always clamped to 0-100."""
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


__all__ = [
    "clamp_score",
    "severity_baseline_score",
    "resolve_alert_risk_score",
    "build_rule_provenance",
]
