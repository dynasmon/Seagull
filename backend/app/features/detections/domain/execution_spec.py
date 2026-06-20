from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Mapping

from app.shared.detection_rules.condition_ast import DetectionBlock
from app.shared.detection_rules.rule_types import V2_RULE_SCHEMA_VERSION


@dataclass(frozen=True)
class RuleExecutionSpec:
    rule_id: str
    schema_version: int
    aggregation_type: str
    group_fields: tuple[str, ...]
    window: timedelta
    cooldown: timedelta
    severity: str
    condition: dict[str, Any] = field(default_factory=dict)
    min_events: int = 0
    match: dict[str, Any] = field(default_factory=dict)
    detection: DetectionBlock | None = None
    distinct_field: str | None = None
    distinct_conditions: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    source_file: str | None = None


def _parse_window(raw: Any) -> int:
    text = str(raw or "").strip().lower()
    if text.endswith("ms"):
        return int(float(text[:-2]) / 1000.0)
    if text.endswith("s"):
        return int(float(text[:-1]))
    if text.endswith("m"):
        return int(float(text[:-1]) * 60)
    if text.endswith("h"):
        return int(float(text[:-1]) * 3600)
    return int(float(text or 0))


def build_rule_execution_spec(rule: Mapping[str, Any]) -> RuleExecutionSpec:
    schema_version = int(rule.get("schema_version") or 1)
    rule_id = str(rule.get("id") or "").strip()
    severity = str(rule.get("severity") or "low").strip().lower()
    source_file = str(rule.get("source_file") or "").strip() or None

    if schema_version == V2_RULE_SCHEMA_VERSION:
        aggregation = rule.get("aggregation") if isinstance(rule.get("aggregation"), Mapping) else {}
        window = timedelta(seconds=max(1, _parse_window(aggregation.get("window") or rule.get("window") or "5m")))
        cooldown = timedelta(seconds=max(0, _parse_window((rule.get("suppression") or {}).get("cooldown") or rule.get("cooldown") or "10m")))
        group_by = aggregation.get("group_by")
        if isinstance(group_by, str):
            group_fields = (group_by,)
        else:
            group_fields = tuple(str(field_name) for field_name in list(group_by or []) if isinstance(field_name, str))
        condition = aggregation.get("condition") if isinstance(aggregation.get("condition"), Mapping) else {}
        min_events = int(aggregation.get("min_events") or rule.get("min_events") or condition.get("min_events") or 0)
        distinct_conditions = tuple(
            dict(item)
            for item in list(aggregation.get("distinct_conditions") or [])
            if isinstance(item, Mapping)
        )
        return RuleExecutionSpec(
            rule_id=rule_id,
            schema_version=schema_version,
            aggregation_type=str(aggregation.get("type") or "").strip().lower(),
            group_fields=group_fields,
            window=window,
            cooldown=cooldown,
            severity=severity,
            condition=dict(condition),
            min_events=min_events,
            detection=rule.get("detection") if isinstance(rule.get("detection"), DetectionBlock) else None,
            distinct_field=str(aggregation.get("field") or "").strip() or None,
            distinct_conditions=distinct_conditions,
            source_file=source_file,
        )

    window = timedelta(seconds=max(1, _parse_window(rule.get("window") or "5m")))
    cooldown = timedelta(seconds=max(0, _parse_window(rule.get("cooldown") or "10m")))
    group_by = rule.get("group_by")
    if isinstance(group_by, str):
        group_fields = (group_by,)
    else:
        group_fields = tuple(str(field_name) for field_name in list(group_by or []) if isinstance(field_name, str))
    condition = rule.get("condition") if isinstance(rule.get("condition"), Mapping) else {}
    return RuleExecutionSpec(
        rule_id=rule_id,
        schema_version=schema_version,
        aggregation_type=str(rule.get("type") or "").strip().lower(),
        group_fields=group_fields,
        window=window,
        cooldown=cooldown,
        severity=severity,
        condition=dict(condition),
        min_events=int(rule.get("min_events") or condition.get("min_events") or 0),
        match=dict(rule.get("match") or {}),
        distinct_field=str(rule.get("distinct_field") or "").strip() or None,
        distinct_conditions=tuple(
            dict(item)
            for item in list(rule.get("distinct_conditions") or [])
            if isinstance(item, Mapping)
        ),
        source_file=source_file,
    )


def compile_validate_effective_rule(effective: Mapping[str, Any]) -> list[str]:
    schema_version = int(effective.get("schema_version") or 1)

    if schema_version == V2_RULE_SCHEMA_VERSION:
        detection = effective.get("detection")
        if detection is not None and not isinstance(detection, DetectionBlock):
            return [
                "patch overwrites the compiled 'detection' block on this v2 rule — "
                "remove 'detection' from patch; it cannot be replaced via an override"
            ]

    try:
        build_rule_execution_spec(effective)
    except Exception as exc:
        return [f"Rule structure invalid after applying changes: {exc}"]

    return []
