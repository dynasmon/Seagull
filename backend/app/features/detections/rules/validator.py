from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.features.detections.domain.rule_types import (
    SUPPORTED_RULE_MATURITIES,
    SUPPORTED_RULE_SCHEMA_VERSIONS,
    SUPPORTED_RULE_SEVERITIES,
    SUPPORTED_RULE_TYPES,
)
from app.features.detections.domain.validation import (
    DetectionRuleValidationError,
    ensure_mapping,
    ensure_threshold_operator,
    ensure_value_in_set,
)
from app.features.detections.rules.registry import (
    SUPPORTED_RUNTIME_EVENT_FIELDS,
    is_legacy_extra_match_key,
    normalize_group_by_fields,
    normalize_match_fields,
)


def validate_rule_document(rule: Mapping[str, Any]) -> None:
    rule_id = str(rule.get("id") or "").strip()
    if not rule_id:
        raise DetectionRuleValidationError("Rule id is required")

    schema_version = rule.get("schema_version")
    if schema_version is not None:
        try:
            schema_int = int(schema_version)
        except Exception as exc:
            raise DetectionRuleValidationError(f"Invalid schema_version for rule {rule_id}: {schema_version}") from exc
        if schema_int not in SUPPORTED_RULE_SCHEMA_VERSIONS:
            raise DetectionRuleValidationError(f"Unsupported schema_version for rule {rule_id}: {schema_int}")

    if rule.get("type") is not None:
        ensure_value_in_set(rule.get("type"), field_name=f"rule type for {rule_id}", supported=SUPPORTED_RULE_TYPES)
    if rule.get("severity") is not None:
        ensure_value_in_set(
            rule.get("severity"),
            field_name=f"rule severity for {rule_id}",
            supported=SUPPORTED_RULE_SEVERITIES,
        )
    if rule.get("maturity") is not None:
        ensure_value_in_set(
            rule.get("maturity"),
            field_name=f"rule maturity for {rule_id}",
            supported=SUPPORTED_RULE_MATURITIES,
        )

    if rule.get("match") is not None:
        match = ensure_mapping(rule.get("match"), field_name=f"match for {rule_id}")
        normalized = normalize_match_fields(match)
        for key in normalized:
            if is_legacy_extra_match_key(key):
                continue
            base_field = key
            for suffix in ("_not_contains", "_contains_all", "_contains", "_startswith", "_endswith", "_not_in", "_in", "_gte", "_gt", "_lte", "_lt", "_neq"):
                if base_field.endswith(suffix):
                    base_field = base_field[: -len(suffix)]
                    break
            if base_field not in SUPPORTED_RUNTIME_EVENT_FIELDS:
                raise DetectionRuleValidationError(f"Unsupported match field for rule {rule_id}: {base_field}")

    if rule.get("group_by") is not None:
        normalized_group_by = normalize_group_by_fields(rule.get("group_by"))
        fields = [normalized_group_by] if isinstance(normalized_group_by, str) else normalized_group_by
        for field_name in fields:
            if field_name not in SUPPORTED_RUNTIME_EVENT_FIELDS:
                raise DetectionRuleValidationError(f"Unsupported group_by field for rule {rule_id}: {field_name}")

    if rule.get("condition") is not None:
        condition = ensure_mapping(rule.get("condition"), field_name=f"condition for {rule_id}")
        if condition.get("operator") is not None:
            ensure_threshold_operator(str(condition.get("operator")))
