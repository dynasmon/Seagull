from __future__ import annotations

import re
from typing import Any

from app.features.detections.domain.canonical_fields import CANONICAL_FIELD_MAP
from app.features.detections.domain.condition_ast import parse_detection_block
from app.features.detections.domain.operators import split_operator_suffix
from app.features.detections.domain.rule_types import (
    DEFAULT_RULE_SCHEMA_VERSION,
    SUPPORTED_RULE_SCHEMA_VERSIONS,
    V1_RULE_SCHEMA_VERSION,
    V2_RULE_SCHEMA_VERSION,
)
from app.features.detections.domain.validation import (
    DetectionRuleValidationError,
    ensure_mapping,
    ensure_non_empty_string,
    ensure_number,
    ensure_threshold_operator,
    normalize_string_list,
)
from app.features.detections.rules.registry import (
    normalize_group_by_fields,
    normalize_match_fields,
    resolve_runtime_field,
    runtime_field_name,
)

_VERSION_RE = re.compile(r"_v(\d+)$", re.IGNORECASE)
_RUNTIME_TO_CANONICAL_FIELD = {
    runtime_field_name(spec): canonical_name
    for canonical_name, spec in CANONICAL_FIELD_MAP.items()
}
_V1_TO_V2_AGGREGATION_TYPES = {
    "aggregate_count": "threshold",
    "distinct_count": "cardinality",
    "multi_distinct": "multi_cardinality",
}


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = dict(base or {})
    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out.get(key) or {}, value)
        else:
            out[key] = value
    return out


def env_aliases(env_name: str) -> list[str]:
    env = str(env_name or "").strip().lower()
    aliases = [env]
    if env in {"prod", "production"}:
        aliases.extend(["prod", "production"])
    elif env in {"stage", "staging"}:
        aliases.extend(["stage", "staging"])
    elif env in {"dev", "development"}:
        aliases.extend(["dev", "development"])
    elif env in {"homolog", "homologation"}:
        aliases.extend(["homolog", "homologation"])

    out: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        if alias and alias not in seen:
            out.append(alias)
            seen.add(alias)
    return out


def apply_env_overrides(rule: dict[str, Any], env_name: str) -> dict[str, Any]:
    out = dict(rule or {})
    env_overrides = out.get("env_overrides")
    if not isinstance(env_overrides, dict) or not env_overrides:
        return out

    merged = dict(out)
    default_patch = env_overrides.get("default") or env_overrides.get("*")
    if isinstance(default_patch, dict):
        merged = deep_merge(merged, default_patch)

    for alias in env_aliases(env_name):
        patch = env_overrides.get(alias)
        if isinstance(patch, dict):
            merged = deep_merge(merged, patch)

    merged.pop("env_overrides", None)
    return merged


def parse_rule_version(rule_id: str, explicit_version: Any = None) -> int:
    if explicit_version is not None:
        try:
            return max(1, int(explicit_version))
        except Exception:
            pass
    match = _VERSION_RE.search(str(rule_id or "").strip())
    if match:
        try:
            return max(1, int(match.group(1)))
        except Exception:
            pass
    return 1


def resolve_rule_schema_version(raw_rule: dict[str, Any], file_meta: dict[str, Any]) -> int:
    raw_schema = raw_rule.get("schema_version", file_meta.get("schema_version", DEFAULT_RULE_SCHEMA_VERSION))
    try:
        schema_version = int(raw_schema or DEFAULT_RULE_SCHEMA_VERSION)
    except Exception as exc:
        raise DetectionRuleValidationError(f"Invalid schema_version: {raw_schema}") from exc
    if schema_version not in SUPPORTED_RULE_SCHEMA_VERSIONS:
        raise DetectionRuleValidationError(f"Unsupported schema_version: {schema_version}")
    return schema_version


def is_runtime_compatible_rule(rule: dict[str, Any]) -> bool:
    from app.features.detections.domain.rule_types import SUPPORTED_RUNTIME_RULE_SCHEMA_VERSIONS
    try:
        return int(rule.get("schema_version") or DEFAULT_RULE_SCHEMA_VERSION) in SUPPORTED_RUNTIME_RULE_SCHEMA_VERSIONS
    except Exception:
        return False


def runtime_field_to_canonical(field_name: str) -> str:
    runtime_field = resolve_runtime_field(field_name)
    return _RUNTIME_TO_CANONICAL_FIELD.get(runtime_field, runtime_field)


def _common_metadata(
    *,
    normalized: dict[str, Any],
    file_meta: dict[str, Any],
    source_file: str,
    with_source: bool,
    schema_version: int,
    rule_id: str,
) -> dict[str, Any]:
    normalized["pack"] = str(normalized.get("pack") or file_meta.get("pack") or "").strip() or None
    normalized["category"] = str(normalized.get("category") or file_meta.get("category") or "").strip() or None
    normalized["pack_version"] = int(file_meta.get("pack_version") or 1)
    normalized["rule_version"] = parse_rule_version(rule_id, normalized.get("version"))
    normalized["schema_version"] = schema_version
    normalized["maturity"] = (
        str(normalized.get("maturity") or file_meta.get("maturity") or "stable").strip().lower() or "stable"
    )
    normalized["environments"] = [
        env.lower()
        for env in normalize_string_list(normalized.get("environments", file_meta.get("environments")))
    ]
    if with_source:
        normalized["source_file"] = source_file
    return normalized


def _normalize_threshold_condition(condition: Any, *, field_name: str) -> dict[str, Any]:
    if condition is None:
        return {}
    condition_map = ensure_mapping(condition, field_name=field_name)
    out = dict(condition_map)
    if "operator" in condition_map:
        out["operator"] = ensure_threshold_operator(str(condition_map.get("operator")))
    if "value" in condition_map:
        out["value"] = ensure_number(condition_map.get("value"), field_name=f"{field_name}.value")
    if "min_events" in condition_map:
        out["min_events"] = int(ensure_number(condition_map.get("min_events"), field_name=f"{field_name}.min_events"))
    return out


def _normalize_v2_aggregation(aggregation: Any) -> dict[str, Any]:
    if aggregation is None:
        return {}
    aggregation_map = ensure_mapping(aggregation, field_name="aggregation")
    out = dict(aggregation_map)
    if "type" in aggregation_map:
        out["type"] = str(aggregation_map.get("type") or "").strip().lower()
    if "group_by" in aggregation_map:
        out["group_by"] = normalize_group_by_fields(aggregation_map.get("group_by"))
    if "field" in aggregation_map and aggregation_map.get("field") is not None:
        out["field"] = resolve_runtime_field(ensure_non_empty_string(aggregation_map.get("field"), field_name="aggregation.field"))
    if "condition" in aggregation_map:
        out["condition"] = _normalize_threshold_condition(
            aggregation_map.get("condition"),
            field_name="aggregation.condition",
        )
    if "min_events" in aggregation_map:
        out["min_events"] = int(ensure_number(aggregation_map.get("min_events"), field_name="aggregation.min_events"))
    if "distinct_conditions" in aggregation_map:
        normalized_conditions: list[dict[str, Any]] = []
        for index, raw_condition in enumerate(aggregation_map.get("distinct_conditions") or []):
            condition_map = ensure_mapping(
                raw_condition,
                field_name=f"aggregation.distinct_conditions[{index}]",
            )
            normalized_conditions.append(
                {
                    "field": resolve_runtime_field(
                        ensure_non_empty_string(condition_map.get("field"), field_name=f"aggregation.distinct_conditions[{index}].field")
                    ),
                    "operator": ensure_threshold_operator(str(condition_map.get("operator") or ">=")),
                    "value": ensure_number(
                        condition_map.get("value"),
                        field_name=f"aggregation.distinct_conditions[{index}].value",
                    ),
                }
            )
        out["distinct_conditions"] = normalized_conditions
    return out


def normalize_v1_match_to_v2_selection(match: Any) -> dict[str, Any]:
    normalized_match = normalize_match_fields(match or {})
    selection: dict[str, Any] = {}
    for raw_key, value in normalized_match.items():
        key = str(raw_key or "").strip()
        if key.startswith("extra_"):
            selection[key] = value
            continue
        field_name, operator = split_operator_suffix(key)
        canonical_field = runtime_field_to_canonical(field_name)
        if operator == "eq":
            selection[canonical_field] = value
        else:
            selection[f"{canonical_field}|{operator}"] = value
    return selection


def _normalize_v1_group_by_to_v2(group_by: Any) -> str | list[str] | None:
    normalized_group_by = normalize_group_by_fields(group_by)
    if normalized_group_by is None:
        return None
    if isinstance(normalized_group_by, str):
        return runtime_field_to_canonical(normalized_group_by)
    return [runtime_field_to_canonical(field_name) for field_name in normalized_group_by]


def _normalize_v1_distinct_conditions_to_v2(distinct_conditions: Any) -> list[dict[str, Any]]:
    if not isinstance(distinct_conditions, list):
        return []
    out: list[dict[str, Any]] = []
    for condition in distinct_conditions:
        if not isinstance(condition, dict):
            continue
        field_name = condition.get("field")
        if not isinstance(field_name, str) or not field_name.strip():
            continue
        out.append(
            {
                "field": runtime_field_to_canonical(field_name),
                "operator": ensure_threshold_operator(str(condition.get("operator") or ">=")),
                "value": ensure_number(condition.get("value"), field_name=f"{field_name}.value"),
            }
        )
    return out


def normalize_v1_rule_to_v2(rule: dict[str, Any]) -> dict[str, Any]:
    rule_id = ensure_non_empty_string(rule.get("id"), field_name="rule id")
    rule_type = str(rule.get("type") or "").strip()
    aggregation_type = _V1_TO_V2_AGGREGATION_TYPES.get(rule_type, "threshold")
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    mitigation = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}

    response: dict[str, Any] = {}
    if rule.get("response"):
        if isinstance(rule.get("response"), dict):
            response.update(rule.get("response"))
        else:
            response["playbook"] = str(rule.get("response"))
    if rule.get("false_positives"):
        response["false_positives"] = rule.get("false_positives")

    logsource: dict[str, Any] = {}
    if rule.get("source"):
        logsource["source"] = str(rule.get("source"))
    if match.get("event_type"):
        logsource["event_type"] = match.get("event_type")

    aggregation: dict[str, Any] = {
        "type": aggregation_type,
        "window": rule.get("window"),
        "group_by": _normalize_v1_group_by_to_v2(rule.get("group_by")),
        "condition": _normalize_threshold_condition(
            rule.get("condition") or {},
            field_name=f"{rule_id}.condition",
        ),
    }
    min_events = rule.get("min_events")
    if min_events is not None:
        aggregation["min_events"] = int(ensure_number(min_events, field_name=f"{rule_id}.min_events"))

    if aggregation_type == "cardinality":
        distinct_field = rule.get("distinct_field")
        if isinstance(distinct_field, str) and distinct_field.strip():
            aggregation["field"] = runtime_field_to_canonical(distinct_field)
    if aggregation_type == "multi_cardinality":
        aggregation["distinct_conditions"] = _normalize_v1_distinct_conditions_to_v2(rule.get("distinct_conditions"))

    status = str(rule.get("status") or ("disabled" if rule.get("enabled") is False else "active")).strip().lower()
    confidence = rule.get("confidence")
    if confidence is None and isinstance(mitigation, dict):
        confidence = mitigation.get("confidence")

    suppression = {
        "cooldown": rule.get("cooldown"),
        "rules": list(rule.get("suppressions") or []),
    }

    normalized = {
        "schema_version": V2_RULE_SCHEMA_VERSION,
        "id": rule_id,
        "name": rule.get("name"),
        "description": rule.get("description"),
        "enabled": rule.get("enabled", True),
        "status": status,
        "maturity": rule.get("maturity"),
        "severity": rule.get("severity"),
        "risk_score": rule.get("risk_score"),
        "confidence": confidence,
        "logsource": logsource,
        "attack": mitigation,
        "detection": {
            "selection": normalize_v1_match_to_v2_selection(match),
            "condition": "selection",
        },
        "aggregation": aggregation,
        "suppression": suppression,
        "tuning": rule.get("tuning") if isinstance(rule.get("tuning"), dict) else {},
        "response": response,
        "tests": list(rule.get("tests") or []),
    }

    for extra_key in ("pack", "category", "pack_version", "source_file", "environments", "rule_version"):
        if extra_key in rule:
            normalized[extra_key] = rule.get(extra_key)
    return normalized


def _normalize_v1_rule_document(
    *,
    normalized: dict[str, Any],
    file_meta: dict[str, Any],
    source_file: str,
    with_source: bool,
    rule_id: str,
) -> dict[str, Any]:
    normalized = _common_metadata(
        normalized=normalized,
        file_meta=file_meta,
        source_file=source_file,
        with_source=with_source,
        schema_version=V1_RULE_SCHEMA_VERSION,
        rule_id=rule_id,
    )

    suppressions = normalized.get("suppressions")
    normalized["suppressions"] = suppressions if isinstance(suppressions, list) else []
    tuning = normalized.get("tuning")
    normalized["tuning"] = tuning if isinstance(tuning, dict) else {}

    if "match" in normalized:
        normalized["match"] = normalize_match_fields(normalized.get("match"))
    if "group_by" in normalized:
        normalized["group_by"] = normalize_group_by_fields(normalized.get("group_by"))
    return normalized


def _normalize_v2_rule_document(
    *,
    normalized: dict[str, Any],
    file_meta: dict[str, Any],
    source_file: str,
    with_source: bool,
    rule_id: str,
) -> dict[str, Any]:
    normalized = _common_metadata(
        normalized=normalized,
        file_meta=file_meta,
        source_file=source_file,
        with_source=with_source,
        schema_version=V2_RULE_SCHEMA_VERSION,
        rule_id=rule_id,
    )

    logsource = normalized.get("logsource")
    normalized["logsource"] = dict(ensure_mapping(logsource or {}, field_name=f"{rule_id}.logsource"))
    attack = normalized.get("attack")
    normalized["attack"] = dict(ensure_mapping(attack or {}, field_name=f"{rule_id}.attack"))
    response = normalized.get("response")
    normalized["response"] = dict(ensure_mapping(response or {}, field_name=f"{rule_id}.response"))
    suppression = normalized.get("suppression")
    normalized["suppression"] = dict(ensure_mapping(suppression or {}, field_name=f"{rule_id}.suppression"))
    tuning = normalized.get("tuning")
    normalized["tuning"] = dict(ensure_mapping(tuning or {}, field_name=f"{rule_id}.tuning"))
    tests = normalized.get("tests")
    normalized["tests"] = list(tests or []) if isinstance(tests, list) else []

    normalized["detection"] = parse_detection_block(normalized.get("detection"))
    normalized["aggregation"] = _normalize_v2_aggregation(normalized.get("aggregation"))
    return normalized


def normalize_rule_document(
    *,
    raw_rule: dict[str, Any],
    file_meta: dict[str, Any],
    env_name: str,
    source_file: str,
    with_source: bool,
) -> dict[str, Any] | None:
    rule_id = str(raw_rule.get("id") or "").strip()
    if not rule_id:
        return None

    normalized = apply_env_overrides(dict(raw_rule), env_name)
    schema_version = resolve_rule_schema_version(normalized, file_meta)
    if schema_version == V2_RULE_SCHEMA_VERSION:
        return _normalize_v2_rule_document(
            normalized=normalized,
            file_meta=file_meta,
            source_file=source_file,
            with_source=with_source,
            rule_id=rule_id,
        )
    return _normalize_v1_rule_document(
        normalized=normalized,
        file_meta=file_meta,
        source_file=source_file,
        with_source=with_source,
        rule_id=rule_id,
    )
