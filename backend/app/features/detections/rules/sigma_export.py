from __future__ import annotations

import logging
from datetime import date
from typing import Any

import yaml

from app.features.detections.domain.condition_ast import (
    DetectionBlock,
    FieldPredicate,
    parse_detection_block,
)
from app.features.detections.domain.rule_types import V2_RULE_SCHEMA_VERSION
from app.features.detections.rules.loader import load_rules

logger = logging.getLogger("seagull.detections.sigma_export")

_STATUS_MAP = {"active": "stable", "disabled": "deprecated"}
_LEVELS = frozenset({"low", "medium", "high", "critical"})
_OPERATOR_SUFFIX = {
    "contains": "|contains",
    "startswith": "|startswith",
    "endswith": "|endswith",
    "in": "|in",
    "contains_all": "|contains|all",
    "gt": "|gt",
    "gte": "|gte",
    "lt": "|lt",
    "lte": "|lte",
}


def _detection_block(rule: dict) -> DetectionBlock:
    detection = rule.get("detection")
    if isinstance(detection, DetectionBlock):
        return detection
    return parse_detection_block(detection)


def _sigma_predicate(predicate: FieldPredicate) -> tuple[str, Any, bool]:
    field = predicate.field
    operator = predicate.operator
    value = predicate.value
    if operator == "eq":
        return field, value, False
    if operator == "not_contains":
        return f"{field}|contains", value, True
    if operator == "not_in":
        return f"{field}|in", value, True
    if operator == "neq":
        return field, value, True
    if operator == "exists":
        return f"{field}|exists", True, False
    if operator == "not_exists":
        return f"{field}|exists", False, False
    suffix = _OPERATOR_SUFFIX.get(operator)
    if suffix:
        return f"{field}{suffix}", value, False
    return field, value, False


def _sigma_detection(block: DetectionBlock) -> dict[str, Any]:
    detection: dict[str, Any] = {}
    filter_not: dict[str, Any] = {}
    for selection in block.selections:
        converted: dict[str, Any] = {}
        for predicate in selection.predicates:
            key, value, is_filter = _sigma_predicate(predicate)
            if is_filter:
                filter_not[key] = value
            else:
                converted[key] = value
        detection[selection.name] = converted
    if filter_not:
        detection["filter_not"] = filter_not
    detection["condition"] = block.condition.raw
    return detection


def _false_positives(rule: dict) -> list[str]:
    response = rule.get("response") if isinstance(rule.get("response"), dict) else {}
    raw = response.get("false_positives")
    if raw is None:
        raw = rule.get("false_positives")
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw if str(item).strip()]
    text = str(raw).strip()
    return [text] if text else []


def _attack_tags(rule: dict) -> list[str]:
    attack = rule.get("attack") if isinstance(rule.get("attack"), dict) else {}
    technique_id = str(attack.get("technique_id") or "").strip()
    if not technique_id:
        return []
    return [f"attack.{technique_id.lower()}"]


def export_rule_to_sigma(rule: dict) -> dict:
    block = _detection_block(rule)
    severity = str(rule.get("severity") or "medium").strip().lower()
    level = severity if severity in _LEVELS else "medium"
    rule_id = str(rule.get("id") or "").strip()
    return {
        "title": str(rule.get("name") or rule_id),
        "id": rule_id,
        "status": _STATUS_MAP.get(str(rule.get("status") or "").strip().lower(), "experimental"),
        "description": str(rule.get("description") or ""),
        "author": "seagull",
        "date": date.today().isoformat(),
        "logsource": dict(rule.get("logsource") or {}),
        "detection": _sigma_detection(block),
        "condition": block.condition.raw,
        "falsepositives": _false_positives(rule),
        "level": level,
        "tags": _attack_tags(rule),
    }


def export_pack_to_sigma(rules: list[dict]) -> str:
    documents: list[dict[str, Any]] = []
    for rule in rules:
        if int(rule.get("schema_version") or 1) != V2_RULE_SCHEMA_VERSION:
            logger.warning("sigma_export_skip_non_v2 rule_id=%s", rule.get("id"))
            continue
        documents.append(export_rule_to_sigma(rule))
    if not documents:
        return ""
    return yaml.safe_dump_all(documents, sort_keys=False, allow_unicode=False, explicit_start=True)


def export_pack_sigma_yaml(*, pack: str, include_disabled: bool = False) -> str:
    target = str(pack or "").strip()
    rules = [
        rule
        for rule in load_rules(include_disabled=include_disabled, apply_env_filters=False)
        if str(rule.get("pack") or "").strip() == target
    ]
    return export_pack_to_sigma(rules)


__all__ = [
    "export_pack_sigma_yaml",
    "export_pack_to_sigma",
    "export_rule_to_sigma",
]
