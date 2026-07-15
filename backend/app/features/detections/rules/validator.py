from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.features.detections.domain.condition_ast import DetectionBlock, parse_detection_block
from app.features.detections.domain.operators import split_operator_suffix
from app.features.detections.domain.rule_types import (
    SUPPORTED_RULE_MATURITIES,
    SUPPORTED_RULE_SCHEMA_VERSIONS,
    SUPPORTED_RULE_SEVERITIES,
    SUPPORTED_RULE_STATUSES,
    SUPPORTED_RULE_TYPES,
    SUPPORTED_V2_AGGREGATION_TYPES,
    V1_RULE_SCHEMA_VERSION,
    V2_RULE_SCHEMA_VERSION,
)
from app.features.detections.domain.validation import (
    DetectionRuleValidationError,
    ensure_mapping,
    ensure_non_empty_string,
    ensure_number,
    ensure_sequence,
    ensure_threshold_operator,
    ensure_value_in_set,
)
from app.features.detections.rules.registry import (
    SUPPORTED_RUNTIME_EVENT_FIELDS,
    is_legacy_extra_match_key,
    normalize_group_by_fields,
    normalize_match_fields,
    resolve_runtime_field,
)

_SUPPORTED_TEST_EXPECTATIONS = frozenset({"hit", "no_hit", "match", "no_match"})


def _validate_tests(rule_id: str, tests: Any) -> None:
    if tests is None:
        return
    test_list = ensure_sequence(tests, field_name=f"tests for {rule_id}")
    seen_ids: set[str] = set()
    for index, raw_test in enumerate(test_list):
        test_map = ensure_mapping(raw_test, field_name=f"tests[{index}] for {rule_id}")
        identifier = str(test_map.get("id") or test_map.get("name") or "").strip()
        if identifier:
            if identifier in seen_ids:
                raise DetectionRuleValidationError(f"Duplicate test id for rule {rule_id}: {identifier}")
            seen_ids.add(identifier)
        expectation = test_map.get("expect")
        if expectation is None:
            expectation = test_map.get("expected")
        if str(expectation or "").strip() == "":
            raise DetectionRuleValidationError(f"tests[{index}] for {rule_id} must define expect")
        ensure_value_in_set(
            expectation,
            field_name=f"tests[{index}].expect for {rule_id}",
            supported=_SUPPORTED_TEST_EXPECTATIONS,
        )
        ensure_sequence(test_map.get("events"), field_name=f"tests[{index}].events for {rule_id}")


def _validate_v1_match(rule_id: str, match: Mapping[str, Any]) -> None:
    normalized = normalize_match_fields(match)
    for key in normalized:
        if is_legacy_extra_match_key(key):
            continue
        base_field, _ = split_operator_suffix(key)
        if base_field not in SUPPORTED_RUNTIME_EVENT_FIELDS:
            raise DetectionRuleValidationError(f"Unsupported match field for rule {rule_id}: {base_field}")


def _validate_group_by(rule_id: str, group_by: Any) -> None:
    normalized_group_by = normalize_group_by_fields(group_by)
    fields = [normalized_group_by] if isinstance(normalized_group_by, str) else normalized_group_by
    for field_name in fields:
        if field_name not in SUPPORTED_RUNTIME_EVENT_FIELDS:
            raise DetectionRuleValidationError(f"Unsupported group_by field for rule {rule_id}: {field_name}")


def _validate_v1_rule_document(rule: Mapping[str, Any], rule_id: str) -> None:
    if rule.get("type") is not None:
        ensure_value_in_set(rule.get("type"), field_name=f"rule type for {rule_id}", supported=SUPPORTED_RULE_TYPES)
    if rule.get("match") is not None:
        _validate_v1_match(rule_id, ensure_mapping(rule.get("match"), field_name=f"match for {rule_id}"))
    if rule.get("group_by") is not None:
        _validate_group_by(rule_id, rule.get("group_by"))
    if rule.get("condition") is not None:
        condition = ensure_mapping(rule.get("condition"), field_name=f"condition for {rule_id}")
        if condition.get("operator") is not None:
            ensure_threshold_operator(str(condition.get("operator")))
    if str(rule.get("type") or "").strip() == "multi_distinct":
        distinct_conditions = rule.get("distinct_conditions") or []
        if not isinstance(distinct_conditions, list) or not distinct_conditions:
            raise DetectionRuleValidationError(f"multi_distinct rule {rule_id} must define distinct_conditions")
        for index, raw_condition in enumerate(distinct_conditions):
            condition = ensure_mapping(raw_condition, field_name=f"distinct_conditions[{index}] for {rule_id}")
            resolve_runtime_field(ensure_non_empty_string(condition.get("field"), field_name=f"distinct_conditions[{index}].field"))
            ensure_threshold_operator(str(condition.get("operator") or ">="))
            ensure_number(condition.get("value"), field_name=f"distinct_conditions[{index}].value")


def _validate_v2_detection(rule_id: str, detection: Any) -> None:
    parsed = detection if isinstance(detection, DetectionBlock) else parse_detection_block(detection)
    if not parsed.selections:
        raise DetectionRuleValidationError(f"V2 rule {rule_id} must define at least one detection selection")


def _validate_v2_aggregation(rule_id: str, aggregation: Any) -> None:
    aggregation_map = ensure_mapping(aggregation or {}, field_name=f"aggregation for {rule_id}")
    aggregation_type = ensure_value_in_set(
        aggregation_map.get("type"),
        field_name=f"aggregation type for {rule_id}",
        supported=SUPPORTED_V2_AGGREGATION_TYPES,
    )
    if aggregation_map.get("group_by") is not None:
        _validate_group_by(rule_id, aggregation_map.get("group_by"))
    if aggregation_map.get("field") is not None:
        resolve_runtime_field(ensure_non_empty_string(aggregation_map.get("field"), field_name=f"aggregation.field for {rule_id}"))
    if aggregation_map.get("condition") is not None:
        condition = ensure_mapping(aggregation_map.get("condition"), field_name=f"aggregation.condition for {rule_id}")
        if condition.get("operator") is not None:
            ensure_threshold_operator(str(condition.get("operator")))
        if condition.get("value") is not None:
            ensure_number(condition.get("value"), field_name=f"aggregation.condition.value for {rule_id}")
    if aggregation_map.get("min_events") is not None:
        ensure_number(aggregation_map.get("min_events"), field_name=f"aggregation.min_events for {rule_id}")
    if aggregation_type == "cardinality" and aggregation_map.get("field") is None:
        raise DetectionRuleValidationError(f"cardinality aggregation for {rule_id} requires field")
    if aggregation_type == "multi_cardinality":
        distinct_conditions = ensure_sequence(
            aggregation_map.get("distinct_conditions") or [],
            field_name=f"aggregation.distinct_conditions for {rule_id}",
        )
        if not distinct_conditions:
            raise DetectionRuleValidationError(f"multi_cardinality aggregation for {rule_id} requires distinct_conditions")
        for index, raw_condition in enumerate(distinct_conditions):
            condition = ensure_mapping(
                raw_condition,
                field_name=f"aggregation.distinct_conditions[{index}] for {rule_id}",
            )
            resolve_runtime_field(
                ensure_non_empty_string(
                    condition.get("field"),
                    field_name=f"aggregation.distinct_conditions[{index}].field for {rule_id}",
                )
            )
            ensure_threshold_operator(str(condition.get("operator") or ">="))
            ensure_number(
                condition.get("value"),
                field_name=f"aggregation.distinct_conditions[{index}].value for {rule_id}",
            )


def _validate_v2_rule_document(rule: Mapping[str, Any], rule_id: str) -> None:
    if rule.get("status") is not None:
        ensure_value_in_set(rule.get("status"), field_name=f"rule status for {rule_id}", supported=SUPPORTED_RULE_STATUSES)
    if rule.get("risk_score") is not None:
        ensure_number(rule.get("risk_score"), field_name=f"risk_score for {rule_id}", minimum=0, maximum=100)
    if rule.get("confidence") is not None:
        ensure_number(rule.get("confidence"), field_name=f"confidence for {rule_id}", minimum=0, maximum=100)
    if rule.get("logsource") is not None:
        ensure_mapping(rule.get("logsource"), field_name=f"logsource for {rule_id}")
    if rule.get("attack") is not None:
        ensure_mapping(rule.get("attack"), field_name=f"attack for {rule_id}")
    _validate_v2_detection(rule_id, rule.get("detection"))
    _validate_v2_aggregation(rule_id, rule.get("aggregation"))
    if rule.get("suppression") is not None:
        ensure_mapping(rule.get("suppression"), field_name=f"suppression for {rule_id}")
    if rule.get("tuning") is not None:
        ensure_mapping(rule.get("tuning"), field_name=f"tuning for {rule_id}")
    if rule.get("response") is not None:
        ensure_mapping(rule.get("response"), field_name=f"response for {rule_id}")


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
    else:
        schema_int = V1_RULE_SCHEMA_VERSION

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

    _validate_tests(rule_id, rule.get("tests"))

    if schema_int == V2_RULE_SCHEMA_VERSION:
        _validate_v2_rule_document(rule, rule_id)
        return
    _validate_v1_rule_document(rule, rule_id)
