from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from app.features.detections.domain.condition_ast import (
    BinaryExpression,
    DetectionBlock,
    FieldPredicate,
    PatternReference,
    SelectionReference,
    UnaryExpression,
)
from app.features.detections.domain.rule_types import V2_RULE_SCHEMA_VERSION
from app.features.detections.testing.fixtures import normalize_event_document


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


def _coerce_num(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _eq(left: Any, right: Any) -> bool:
    if isinstance(right, bool):
        return str(left).strip().lower() == ("true" if right else "false")
    return str(left) == str(right)


def _evaluate_op(actual: Any, operator: str, expected: Any) -> bool:
    if operator in {"contains", "not_contains", "contains_all", "startswith", "endswith"}:
        terms = expected if isinstance(expected, list) else [expected]
        normalized_terms = [str(item).strip().lower() for item in terms if str(item).strip()]
        if not normalized_terms:
            return False
        text = str(actual or "").lower()
        if operator == "contains":
            return any(term in text for term in normalized_terms)
        if operator == "contains_all":
            return all(term in text for term in normalized_terms)
        if operator == "not_contains":
            return all(term not in text for term in normalized_terms)
        if operator == "startswith":
            return any(text.startswith(term) for term in normalized_terms)
        return any(text.endswith(term) for term in normalized_terms)

    if operator in {"in", "not_in"}:
        items = expected if isinstance(expected, list) else [expected]
        matched = any(_eq(actual, item) for item in items)
        return matched if operator == "in" else not matched

    if operator in {"gte", "gt", "lte", "lt"}:
        left = _coerce_num(actual)
        right = _coerce_num(expected)
        if left is None or right is None:
            return False
        if operator == "gte":
            return left >= right
        if operator == "gt":
            return left > right
        if operator == "lte":
            return left <= right
        return left < right

    if operator == "neq":
        return not _eq(actual, expected)
    if operator == "exists":
        return actual is not None and str(actual).strip() != ""
    if operator == "not_exists":
        return actual is None or str(actual).strip() == ""
    return _eq(actual, expected)


def _parse_v1_field_operator(raw_key: str) -> tuple[str | None, str | None]:
    for suffix, operator in (
        ("_not_contains", "not_contains"),
        ("_contains_all", "contains_all"),
        ("_contains", "contains"),
        ("_startswith", "startswith"),
        ("_endswith", "endswith"),
        ("_not_exists", "not_exists"),
        ("_exists", "exists"),
        ("_not_in", "not_in"),
        ("_in", "in"),
        ("_gte", "gte"),
        ("_gt", "gt"),
        ("_lte", "lte"),
        ("_lt", "lt"),
        ("_neq", "neq"),
    ):
        if raw_key.endswith(suffix):
            return raw_key[: -len(suffix)], operator
    return None, None


def _event_matches_v1(match: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    extra = event.get("extra") if isinstance(event.get("extra"), dict) else {}

    for key, expected in (match or {}).items():
        if key in event:
            if not _eq(event.get(key), expected):
                return False
            continue

        base_field, operator = _parse_v1_field_operator(str(key))
        if base_field and operator and base_field in event:
            if not _evaluate_op(event.get(base_field), operator, expected):
                return False
            continue

        if not str(key).startswith("extra_"):
            continue

        extra_key = str(key)[len("extra_") :]
        operator = "eq"
        for suffix, operator_name in (
            ("_not_contains", "not_contains"),
            ("_contains_all", "contains_all"),
            ("_contains", "contains"),
            ("_startswith", "startswith"),
            ("_endswith", "endswith"),
            ("_not_exists", "not_exists"),
            ("_exists", "exists"),
            ("_not_in", "not_in"),
            ("_in", "in"),
            ("_gte", "gte"),
            ("_gt", "gt"),
            ("_lte", "lte"),
            ("_lt", "lt"),
            ("_neq", "neq"),
        ):
            if extra_key.endswith(suffix):
                extra_key = extra_key[: -len(suffix)]
                operator = operator_name
                break
        if not _evaluate_op(extra.get(extra_key), operator, expected):
            return False

    return True


def _predicate_matches(predicate: FieldPredicate, event: Mapping[str, Any]) -> bool:
    return _evaluate_op(event.get(predicate.runtime_field or predicate.field), predicate.operator, predicate.value)


def _selection_matches(event: Mapping[str, Any], detection: DetectionBlock) -> dict[str, bool]:
    return {
        selection.name: all(_predicate_matches(predicate, event) for predicate in selection.predicates)
        for selection in detection.selections
    }


def _evaluate_detection_expression(node: Any, selection_hits: Mapping[str, bool]) -> bool:
    if isinstance(node, SelectionReference):
        return bool(selection_hits.get(node.name))
    if isinstance(node, PatternReference):
        values = [bool(selection_hits.get(name)) for name in node.matches]
        if node.quantifier == "all":
            return all(values)
        return sum(1 for value in values if value) >= int(node.quantifier)
    if isinstance(node, UnaryExpression):
        return not _evaluate_detection_expression(node.operand, selection_hits)
    if isinstance(node, BinaryExpression):
        left = _evaluate_detection_expression(node.left, selection_hits)
        right = _evaluate_detection_expression(node.right, selection_hits)
        if node.operator == "and":
            return left and right
        return left or right
    return False


def _event_matches_v2(detection: DetectionBlock, event: Mapping[str, Any]) -> bool:
    selection_hits = _selection_matches(event, detection)
    return _evaluate_detection_expression(detection.condition.expression, selection_hits)


def _condition_ok(value: int, condition: Mapping[str, Any]) -> bool:
    operator = str((condition or {}).get("operator") or ">=").strip()
    target = int((condition or {}).get("value") or 0)
    if operator == ">=":
        return value >= target
    if operator == ">":
        return value > target
    if operator == "<=":
        return value <= target
    if operator == "<":
        return value < target
    if operator == "==":
        return value == target
    if operator == "!=":
        return value != target
    return value >= target


def _group_key(group_fields: tuple[str, ...], event: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(event.get(field_name) for field_name in group_fields)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _as_group_dict(group_fields: tuple[str, ...], group_key: tuple[Any, ...]) -> dict[str, Any]:
    return dict(zip(group_fields, group_key, strict=False))


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


def event_matches_rule(spec: RuleExecutionSpec, event: Mapping[str, Any]) -> bool:
    if spec.schema_version == V2_RULE_SCHEMA_VERSION:
        return bool(spec.detection) and _event_matches_v2(spec.detection, event)
    return _event_matches_v1(spec.match, event)


def evaluate_group_window(spec: RuleExecutionSpec, rows: list[Mapping[str, Any]]) -> dict[str, Any] | None:
    if spec.min_events and len(rows) < spec.min_events:
        return None

    if spec.aggregation_type in {"aggregate_count", "threshold"}:
        count = len(rows)
        if _condition_ok(count, spec.condition):
            return {"count": count}
        return None

    if spec.aggregation_type in {"distinct_count", "cardinality"}:
        if not spec.distinct_field:
            return None
        values = {row.get(spec.distinct_field) for row in rows if row.get(spec.distinct_field) is not None}
        distinct_count = len(values)
        if _condition_ok(distinct_count, spec.condition):
            return {"distinct_count": distinct_count, "event_count": len(rows)}
        return None

    if spec.aggregation_type in {"multi_distinct", "multi_cardinality"}:
        if not spec.distinct_conditions:
            return None
        distinct: dict[str, int] = {}
        for condition in spec.distinct_conditions:
            field_name = str(condition.get("field") or "").strip()
            if not field_name:
                return None
            distinct[field_name] = len({row.get(field_name) for row in rows if row.get(field_name) is not None})
            if not _condition_ok(distinct[field_name], condition):
                return None
        return {"distinct": distinct, "event_count": len(rows)}

    return None


def evaluate_detection_rule(rule: Mapping[str, Any], events: list[Mapping[str, Any]], now: datetime) -> list[dict[str, Any]]:
    spec = build_rule_execution_spec(rule)
    if not spec.group_fields:
        return []

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    since = now - spec.window

    grouped_rows: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for raw_event in events:
        event = normalize_event_document(raw_event)
        if event["timestamp"] < since or event["timestamp"] > now:
            continue
        if not event_matches_rule(spec, event):
            continue
        grouped_rows[_group_key(spec.group_fields, event)].append(event)

    hits: list[dict[str, Any]] = []
    for group_key, rows in grouped_rows.items():
        result = evaluate_group_window(spec, rows)
        if result is None:
            continue
        hit = {"group_key": _as_group_dict(spec.group_fields, group_key)}
        hit.update(result)
        hits.append(hit)
    return hits


def _derive_test_now(raw_test: Mapping[str, Any]) -> datetime:
    events = list(raw_test.get("events") or [])
    timestamps: list[datetime] = []
    for raw_event in events:
        if not isinstance(raw_event, Mapping):
            continue
        try:
            event = normalize_event_document(raw_event)
        except Exception:
            continue
        timestamps.append(event["timestamp"])
    if timestamps:
        return max(timestamps)
    return datetime.now(timezone.utc)


def run_rule_yaml_tests(rule: Mapping[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for index, raw_test in enumerate(list(rule.get("tests") or [])):
        name = f"test_{index + 1}"
        expected = ""
        events: list[Mapping[str, Any]] = []
        error: str | None = None

        if isinstance(raw_test, Mapping):
            candidate_name = str(raw_test.get("name") or "").strip()
            if candidate_name:
                name = candidate_name
            expected = str(raw_test.get("expected") or "").strip().lower()
            if isinstance(raw_test.get("events"), list):
                events = [event for event in raw_test.get("events") or [] if isinstance(event, Mapping)]
            else:
                error = "tests.events must be a list"
        else:
            error = "tests entries must be mappings"

        if error is None and expected not in {"match", "no_match"}:
            error = f"Unsupported test expectation: {expected or '<empty>'}"

        hit_count = 0
        preview = None
        actual = "error"
        passed = False

        if error is None:
            hits = evaluate_detection_rule(rule, events, _derive_test_now(raw_test if isinstance(raw_test, Mapping) else {}))
            hit_count = len(hits)
            preview = hits[0] if hits else None
            actual = "match" if hit_count > 0 else "no_match"
            passed = actual == expected

        results.append(
            {
                "rule_id": str(rule.get("id") or "").strip() or None,
                "source_file": str(rule.get("source_file") or "").strip() or None,
                "name": name,
                "expected": expected or None,
                "actual": actual,
                "passed": passed,
                "hit_count": hit_count,
                "preview": preview,
                "error": error,
            }
        )

    return results


def run_yaml_rule_suite(rules: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for rule in rules:
        results.extend(run_rule_yaml_tests(rule))
    return results


def summarize_hit_entities(hits: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    entities: dict[str, dict[str, Any]] = {}
    for hit in hits:
        group_key = dict(hit.get("group_key") or {})
        signature = _stable_json(group_key)
        bucket = entities.setdefault(signature, {"group_key": group_key, "match_count": 0})
        bucket["match_count"] += 1
    return sorted(entities.values(), key=lambda item: (-int(item["match_count"]), _stable_json(item["group_key"])))


__all__ = [
    "RuleExecutionSpec",
    "build_rule_execution_spec",
    "evaluate_detection_rule",
    "evaluate_group_window",
    "event_matches_rule",
    "run_rule_yaml_tests",
    "run_yaml_rule_suite",
    "summarize_hit_entities",
]
