from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import json
from typing import Any, Mapping

from app.features.detections.domain.canonical_fields import CANONICAL_FIELD_MAP
from app.features.detections.rules.loader import (
    _discover_rule_files,
    _rules_dir_path,
    load_and_validate_rules,
)
from app.features.detections.testing.yaml_tests import run_yaml_rule_suite
from app.features.events.worker_runtime import NetEventModel


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _severity(rule: Mapping[str, Any]) -> str:
    return str(rule.get("severity") or "").strip().lower()


def _rule_mitre(rule: Mapping[str, Any]) -> Mapping[str, Any]:
    schema_version = int(rule.get("schema_version") or 1)
    if schema_version == 2:
        attack = rule.get("attack")
        return attack if isinstance(attack, Mapping) else {}
    mitre = rule.get("mitre")
    return mitre if isinstance(mitre, Mapping) else {}


def _has_mitre_guidance(rule: Mapping[str, Any]) -> bool:
    mitre = _rule_mitre(rule)
    return bool(str(mitre.get("tactic") or "").strip() and str(mitre.get("technique_id") or "").strip())


def _has_response_guidance(rule: Mapping[str, Any]) -> bool:
    response = rule.get("response")
    if isinstance(response, Mapping):
        return bool(str(response.get("playbook") or response.get("summary") or "").strip())
    return bool(str(response or "").strip())


def _has_false_positive_guidance(rule: Mapping[str, Any]) -> bool:
    response = rule.get("response")
    if isinstance(response, Mapping) and str(response.get("false_positives") or "").strip():
        return True
    return bool(str(rule.get("false_positives") or "").strip())


def _warning(*, rule: Mapping[str, Any] | None, code: str, message: str) -> dict[str, Any]:
    return {
        "code": code,
        "rule_id": str((rule or {}).get("id") or "").strip() or None,
        "source_file": str((rule or {}).get("source_file") or "").strip() or None,
        "message": message,
    }


def _error(*, source_file: str | None, message: str, rule_id: str | None = None, code: str | None = None) -> dict[str, Any]:
    payload = {
        "source_file": source_file,
        "rule_id": rule_id,
        "message": message,
    }
    if code:
        payload["code"] = code
    return payload


def _detection_signature(rule: Mapping[str, Any]) -> str | None:
    schema_version = int(rule.get("schema_version") or 1)
    if schema_version == 2:
        detection = rule.get("detection")
        aggregation = rule.get("aggregation") if isinstance(rule.get("aggregation"), Mapping) else {}
        if detection is None:
            return None
        try:
            selections = []
            for selection in detection.selections:
                predicates = sorted(
                    (
                        predicate.runtime_field,
                        predicate.operator,
                        _stable_json(predicate.value),
                    )
                    for predicate in selection.predicates
                )
                selections.append((selection.name, predicates))
            payload = {
                "schema_version": 2,
                "condition": detection.condition.raw,
                "selections": sorted(selections),
                "aggregation_type": aggregation.get("type"),
                "group_by": aggregation.get("group_by"),
                "field": aggregation.get("field"),
                "distinct_conditions": aggregation.get("distinct_conditions"),
            }
            return _stable_json(payload)
        except Exception:
            return None

    payload = {
        "schema_version": 1,
        "match": rule.get("match") or {},
        "aggregation_type": rule.get("type"),
        "group_by": rule.get("group_by"),
        "field": rule.get("distinct_field"),
        "distinct_conditions": rule.get("distinct_conditions"),
    }
    return _stable_json(payload)


def collect_quality_warnings(rules: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []

    for rule in rules:
        if _severity(rule) in {"high", "critical"} and not _has_mitre_guidance(rule):
            warnings.append(
                _warning(
                    rule=rule,
                    code="missing_mitre_metadata",
                    message="High/critical rule is missing MITRE tactic and technique metadata.",
                )
            )
        if not _has_response_guidance(rule):
            warnings.append(
                _warning(
                    rule=rule,
                    code="missing_response_guidance",
                    message="Rule is missing response guidance.",
                )
            )
        if not _has_false_positive_guidance(rule):
            warnings.append(
                _warning(
                    rule=rule,
                    code="missing_false_positive_guidance",
                    message="Rule is missing false positive guidance.",
                )
            )

    by_signature: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for rule in rules:
        signature = _detection_signature(rule)
        if signature:
            by_signature[signature].append(rule)

    for overlap_rules in by_signature.values():
        if len(overlap_rules) < 2:
            continue
        rule_ids = sorted(str(rule.get("id") or "").strip() for rule in overlap_rules if str(rule.get("id") or "").strip())
        warnings.append(
            _warning(
                rule=overlap_rules[0],
                code="suspicious_rule_overlap",
                message=f"Rules share identical detection and aggregation logic: {', '.join(rule_ids)}",
            )
        )

    return warnings


def validate_detection_content(
    *,
    rules_dir: str | Path | None = None,
    apply_env_filters: bool = False,
    include_disabled: bool = True,
    execute_yaml_tests: bool = True,
) -> dict[str, Any]:
    base_dir = _rules_dir_path(rules_dir)
    report = load_and_validate_rules(
        include_disabled=include_disabled,
        with_source=True,
        rules_dir=base_dir,
        apply_env_filters=apply_env_filters,
        strict=False,
        include_non_runtime=True,
    )
    rules = list(report.get("rules") or [])
    errors = list(report.get("errors") or [])
    warnings = collect_quality_warnings(rules)

    for canonical_name, spec in CANONICAL_FIELD_MAP.items():
        if not hasattr(NetEventModel, spec.model_attr):
            errors.append(
                _error(
                    source_file=None,
                    rule_id=None,
                    code="missing_canonical_field",
                    message=f"Canonical field {canonical_name} maps to missing NetEventModel attribute {spec.model_attr}",
                )
            )

    yaml_results = run_yaml_rule_suite(rules) if execute_yaml_tests else []
    for result in yaml_results:
        if result.get("passed"):
            continue
        test_name = str(result.get("name") or "").strip() or "<unnamed>"
        detail = str(result.get("error") or f"expected {result.get('expected')}, got {result.get('actual')}").strip()
        errors.append(
            _error(
                source_file=result.get("source_file"),
                rule_id=result.get("rule_id"),
                code="yaml_rule_test_failed",
                message=f"YAML rule test '{test_name}' failed: {detail}",
            )
        )

    return {
        "passed": len(errors) == 0,
        "rules_dir": str(base_dir),
        "files_scanned": len(_discover_rule_files(base_dir)) if base_dir.exists() else 0,
        "rule_count": len(rules),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "yaml_test_count": len(yaml_results),
        "yaml_failed_count": sum(1 for result in yaml_results if not result.get("passed")),
        "errors": errors,
        "warnings": warnings,
        "yaml_tests": yaml_results,
    }


__all__ = [
    "collect_quality_warnings",
    "validate_detection_content",
]
