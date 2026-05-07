"""Rule governance validation.

Called before persisting any override, tuning, or suppression.
Validates the effective rule and every suppression item before any DB write.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.features.detections.domain.rule_types import (
    SUPPORTED_RULE_SEVERITIES,
    V2_RULE_SCHEMA_VERSION,
)

VALID_SEVERITIES: frozenset[str] = frozenset(SUPPORTED_RULE_SEVERITIES)
_VALID_COND_OPS: frozenset[str] = frozenset({">=", ">", "<=", "<", "==", "!="})
_DURATION_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h)$", re.IGNORECASE)
_HIGH_RISK_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    effective: dict[str, Any] | None = None


def _validate_duration(raw: Any, *, field_name: str) -> list[str]:
    s = str(raw or "").strip()
    if not s:
        return [f"{field_name}: must be a non-empty duration (e.g. '5m', '30s', '1h')"]
    if not _DURATION_RE.match(s):
        return [f"{field_name}: invalid duration '{s}' — use e.g. '5m', '30s', '1h', '500ms'"]
    return []


def _validate_override_fields(body: Any) -> list[str]:
    errors: list[str] = []
    fields_set = getattr(body, "__fields_set__", set())

    if "severity" in fields_set and body.severity is not None:
        if str(body.severity).lower() not in VALID_SEVERITIES:
            errors.append(
                f"severity: '{body.severity}' is not valid — use one of {sorted(VALID_SEVERITIES)}"
            )

    if "window" in fields_set and body.window is not None:
        errors.extend(_validate_duration(body.window, field_name="window"))

    if "cooldown" in fields_set and body.cooldown is not None:
        errors.extend(_validate_duration(body.cooldown, field_name="cooldown"))

    if "min_events" in fields_set and body.min_events is not None:
        if body.min_events < 0:
            errors.append("min_events: must be >= 0")

    if "condition" in fields_set and body.condition is not None:
        c = body.condition
        op = c.get("operator")
        val = c.get("value")
        if op is not None and str(op) not in _VALID_COND_OPS:
            errors.append(
                f"condition.operator: '{op}' is not valid — use one of {sorted(_VALID_COND_OPS)}"
            )
        if val is not None:
            try:
                float(val)
            except (TypeError, ValueError):
                errors.append(f"condition.value: must be numeric, got '{val}'")

    if "patch" in fields_set and body.patch is not None:
        if not isinstance(body.patch, dict):
            errors.append("patch: must be a JSON object")

    if "tuning" in fields_set and body.tuning is not None:
        if not isinstance(body.tuning, dict):
            errors.append("tuning: must be a JSON object")

    return errors


def validate_suppression_item(
    item: dict[str, Any],
    *,
    base_severity: str,
    idx: int,
) -> list[str]:
    """Validate a single suppression dict before persistence."""
    errors: list[str] = []
    prefix = f"suppressions[{idx}]"

    reason = str(item.get("reason") or "").strip()
    if not reason:
        errors.append(f"{prefix}.reason: required — provide a non-empty justification")

    has_until = bool(str(item.get("until") or "").strip())
    is_permanent = bool(item.get("permanent"))
    if not has_until and not is_permanent:
        errors.append(
            f"{prefix}: must specify 'until' (ISO datetime expiration) "
            "or 'permanent: true' for an explicitly permanent suppression"
        )

    when = item.get("when")
    is_broad = not isinstance(when, dict) or not when
    if is_broad and str(base_severity or "").lower() in _HIGH_RISK_SEVERITIES:
        if not bool(item.get("confirm_high_risk")):
            errors.append(
                f"{prefix}: broad suppression (empty 'when' scope) on {base_severity} rule "
                "requires 'confirm_high_risk: true'"
            )

    return errors


def _try_compile_effective(effective: dict[str, Any]) -> list[str]:
    """Attempt structural validation of the effective rule."""
    schema_version = int(effective.get("schema_version") or 1)

    if schema_version == V2_RULE_SCHEMA_VERSION:
        from app.features.detections.domain.condition_ast import DetectionBlock
        detection = effective.get("detection")
        if detection is not None and not isinstance(detection, DetectionBlock):
            return [
                "patch overwrites the compiled 'detection' block on this v2 rule — "
                "remove 'detection' from patch; it cannot be replaced via an override"
            ]

    try:
        from app.features.detections.testing.yaml_tests import build_rule_execution_spec
        build_rule_execution_spec(effective)
    except Exception as exc:
        return [f"Rule structure invalid after applying changes: {exc}"]

    return []


def build_provisional_effective(
    base: dict[str, Any],
    body: Any,
) -> dict[str, Any]:
    """Simulate the effective rule that would result from applying body to base.

    Does not touch the database. Used for pre-save compile validation.
    """
    from app.workers.intelligence.rules.registry import deep_merge

    fields_set = getattr(body, "__fields_set__", set())
    eff = dict(base)

    if "enabled" in fields_set and body.enabled is not None:
        eff["enabled"] = bool(body.enabled)
    if "severity" in fields_set and body.severity is not None:
        eff["severity"] = str(body.severity)
    if "window" in fields_set and body.window is not None:
        eff["window"] = str(body.window)
    if "cooldown" in fields_set and body.cooldown is not None:
        eff["cooldown"] = str(body.cooldown)
    if "min_events" in fields_set and body.min_events is not None:
        eff["min_events"] = int(body.min_events)
    if "condition" in fields_set and isinstance(body.condition, dict) and body.condition:
        eff["condition"] = deep_merge(eff.get("condition") or {}, body.condition)
    if "schedule" in fields_set and isinstance(body.schedule, dict) and body.schedule:
        eff["schedule"] = deep_merge(eff.get("schedule") or {}, body.schedule)
    if "patch" in fields_set and isinstance(body.patch, dict) and body.patch:
        eff = deep_merge(eff, body.patch)
    if "tuning" in fields_set and isinstance(body.tuning, dict):
        eff["tuning"] = body.tuning

    return eff


def validate_governance_request(
    body: Any,
    *,
    base_rule: dict[str, Any],
) -> ValidationResult:
    """Full pre-save validation for overrides, tunings, and suppressions.

    Returns a ValidationResult with ok=True only if all checks pass.
    Errors are actionable messages suitable for display to operators.
    """
    errors: list[str] = []

    errors.extend(_validate_override_fields(body))

    provisional_effective = build_provisional_effective(base_rule, body)
    base_severity = str(provisional_effective.get("severity") or "low").lower()

    fields_set = getattr(body, "__fields_set__", set())
    if "suppressions" in fields_set and body.suppressions is not None:
        for idx, item in enumerate(body.suppressions):
            if not isinstance(item, dict):
                errors.append(f"suppressions[{idx}]: must be a JSON object")
                continue
            errors.extend(
                validate_suppression_item(item, base_severity=base_severity, idx=idx)
            )

    errors.extend(_try_compile_effective(provisional_effective))

    return ValidationResult(
        ok=not errors,
        errors=errors,
        effective=provisional_effective if not errors else None,
    )
