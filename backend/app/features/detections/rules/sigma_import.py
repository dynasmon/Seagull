from __future__ import annotations

import argparse
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
import re
from typing import Any

import yaml

from app.features.detections.domain.rule_types import V2_RULE_SCHEMA_VERSION
from app.features.detections.domain.validation import DetectionRuleValidationError, ensure_mapping, ensure_non_empty_string
from app.features.detections.rules.validator import validate_rule_document


DEFAULT_SIGMA_IMPORT_WINDOW = "5m"
DEFAULT_SIGMA_IMPORT_COOLDOWN = "10m"
DEFAULT_SIGMA_IMPORT_PACK = "sigma"
DEFAULT_SIGMA_IMPORT_CATEGORY = "imported"
_BLOCKED_SELECTION_EVENT_TYPE_PREFIX = "__seagull_sigma_import_blocked__:"
_WINDOW_RE = re.compile(r"^\d+(?:\.\d+)?(?:ms|s|m|h)?$", re.IGNORECASE)

_SUPPORTED_SIGMA_TOP_LEVEL_FIELDS = frozenset(
    {
        "title",
        "id",
        "description",
        "status",
        "level",
        "tags",
        "references",
        "falsepositives",
        "logsource",
        "detection",
    }
)
_SUPPORTED_SIGMA_LOGSOURCE_FIELDS = frozenset({"category", "product", "service"})
_SUPPORTED_SIGMA_DETECTION_META_FIELDS = frozenset({"condition", "timeframe"})

_SIGMA_LEVEL_TO_SEAGULL_SEVERITY = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

_ATTACK_TACTICS = frozenset(
    {
        "reconnaissance",
        "resource_development",
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
    }
)

_ATTACK_TECHNIQUE_NAMES = {
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.004": "SSH",
    "T1036": "Masquerading",
    "T1046": "Network Service Scanning",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1543": "Create or Modify System Process",
    "T1543.002": "Systemd Service",
}

_SIGMA_FIELD_ALIASES = {
    "source.ip": "source.ip",
    "src_ip": "source.ip",
    "sourceip": "source.ip",
    "source.port": "source.port",
    "src_port": "source.port",
    "sourceport": "source.port",
    "destination.ip": "destination.ip",
    "dest_ip": "destination.ip",
    "dst_ip": "destination.ip",
    "destinationip": "destination.ip",
    "destination.port": "destination.port",
    "dest_port": "destination.port",
    "dst_port": "destination.port",
    "destinationport": "destination.port",
    "network.transport": "network.transport",
    "transport": "network.transport",
    "proto": "network.transport",
    "network.protocol": "network.protocol",
    "app_proto": "network.protocol",
    "event.type": "event.type",
    "event_type": "event.type",
    "eventtype": "event.type",
    "user.name": "user.name",
    "user": "user.name",
    "username": "user.name",
    "process.name": "process.name",
    "processname": "process.name",
    "imagename": "process.name",
    "process.executable": "process.executable",
    "image": "process.executable",
    "process.parent.name": "process.parent.name",
    "parentimage": "process.parent.name",
    "parentprocessname": "process.parent.name",
    "file.path": "file.path",
    "targetfilename": "file.path",
    "filepath": "file.path",
    "dns.question.name": "dns.question.name",
    "queryname": "dns.question.name",
    "http.request.host": "http.request.host",
    "httphost": "http.request.host",
    "requesthost": "http.request.host",
    "http.request.method": "http.request.method",
    "httpmethod": "http.request.method",
    "tls.server_name": "tls.server_name",
    "sni": "tls.server_name",
    "tls.ja3": "tls.ja3",
    "ja3": "tls.ja3",
    "tls.ja4": "tls.ja4",
    "ja4": "tls.ja4",
    "ssh.action": "ssh.action",
    "sshaction": "ssh.action",
}

_NAME_ONLY_FIELDS = frozenset({"process.name", "process.parent.name"})


def _warning(
    *,
    code: str,
    path: str,
    message: str,
    value: Any | None = None,
    blocking: bool = True,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "code": code,
        "path": path,
        "message": message,
        "blocking": blocking,
    }
    if value is not None:
        payload["value"] = value
    return payload


def _stable_slug(value: Any, *, default: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
    return text or default


def _coerce_pack_token(value: Any, *, default: str) -> str:
    return _stable_slug(value, default=default)


def _looks_like_uuid(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value.strip().lower()))


def _derive_rule_id(sigma_rule: Mapping[str, Any]) -> str:
    sigma_id = str(sigma_rule.get("id") or "").strip()
    title = ensure_non_empty_string(sigma_rule.get("title"), field_name="Sigma title")

    if sigma_id and not _looks_like_uuid(sigma_id):
        base = _stable_slug(sigma_id, default="sigma_rule")
    else:
        base = _stable_slug(title, default="sigma_rule")

    if not re.search(r"_v\d+$", base):
        base = f"{base}_v1"
    return base


def _normalize_string_items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _blocked_selection(selection_name: str) -> dict[str, Any]:
    return {"event.type": f"{_BLOCKED_SELECTION_EVENT_TYPE_PREFIX}{selection_name}"}


def _normalize_basename(value: str) -> str:
    return re.split(r"[\\/]+", str(value or "").strip())[-1]


def _normalize_name_only_value(canonical_field: str, value: Any) -> Any:
    if canonical_field not in _NAME_ONLY_FIELDS:
        return value
    if isinstance(value, str):
        return _normalize_basename(value)
    if isinstance(value, list):
        return [_normalize_basename(item) if isinstance(item, str) else item for item in value]
    return value


def _normalize_scalar_list(value: Any) -> list[Any] | None:
    if isinstance(value, list):
        if not value:
            return None
        if any(isinstance(item, Mapping) or isinstance(item, list) for item in value):
            return None
        return list(value)
    if isinstance(value, Mapping):
        return None
    return [value]


def _normalize_selection_name(name: str, *, index: int) -> str:
    raw = str(name or "").strip()
    candidate = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_")
    if not candidate:
        candidate = f"selection_{index}"
    if candidate[0].isdigit():
        candidate = f"selection_{candidate}"
    return candidate


def _rewrite_condition_for_seagull(raw_condition: str, name_map: Mapping[str, str]) -> str:
    rewritten = re.sub(r"(?i)\b(all|\d+)\s+of\s+them\b", lambda match: f"{match.group(1)} of *", raw_condition)
    for original, normalized in sorted(name_map.items(), key=lambda item: len(item[0]), reverse=True):
        if original == normalized:
            continue
        pattern = rf"(?<![A-Za-z0-9_*]){re.escape(original)}(?![A-Za-z0-9_*])"
        rewritten = re.sub(pattern, normalized, rewritten)
    return rewritten


def _resolve_sigma_field(raw_field: str) -> str | None:
    key = str(raw_field or "").strip()
    if not key:
        return None
    direct = _SIGMA_FIELD_ALIASES.get(key.lower())
    if direct:
        return direct
    return _SIGMA_FIELD_ALIASES.get(key)


def _parse_sigma_field_key(raw_key: str) -> tuple[str, list[str]]:
    parts = [part.strip() for part in str(raw_key or "").split("|")]
    field_name = str(parts[0] or "").strip()
    modifiers = [part.lower() for part in parts[1:] if str(part or "").strip()]
    return field_name, modifiers


def _coerce_numeric(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value) if float(value).is_integer() else float(value)
    try:
        number = float(str(value).strip())
    except Exception:
        return None
    return int(number) if number.is_integer() else number


def _convert_predicate(
    *,
    canonical_field: str,
    modifiers: list[str],
    raw_value: Any,
    path: str,
    warnings: list[dict[str, Any]],
) -> tuple[str, Any] | None:
    value = _normalize_name_only_value(canonical_field, deepcopy(raw_value))

    if not modifiers:
        if isinstance(value, list):
            items = _normalize_scalar_list(value)
            if items is None:
                warnings.append(
                    _warning(
                        code="unsupported_detection_value",
                        path=path,
                        message="Sigma list values must contain only scalar items.",
                        value=raw_value,
                    )
                )
                return None
            return f"{canonical_field}|in", items
        if isinstance(value, Mapping):
            warnings.append(
                _warning(
                    code="unsupported_detection_value",
                    path=path,
                    message="Sigma mapping values are not supported in detection predicates.",
                    value=raw_value,
                )
            )
            return None
        return canonical_field, value

    if "all" in modifiers:
        remaining = [modifier for modifier in modifiers if modifier != "all"]
        if remaining == ["contains"]:
            items = _normalize_scalar_list(value)
            if items is None:
                warnings.append(
                    _warning(
                        code="unsupported_detection_value",
                        path=path,
                        message="Sigma contains|all requires a scalar or a flat list of scalars.",
                        value=raw_value,
                    )
                )
                return None
            return f"{canonical_field}|contains_all", [str(item) for item in items]
        warnings.append(
            _warning(
                code="unsupported_detection_operator",
                path=path,
                message=f"Unsupported Sigma modifier combination: {'|'.join(modifiers)}",
                value=raw_value,
            )
        )
        return None

    if len(modifiers) != 1:
        warnings.append(
            _warning(
                code="unsupported_detection_operator",
                path=path,
                message=f"Unsupported Sigma modifier combination: {'|'.join(modifiers)}",
                value=raw_value,
            )
        )
        return None

    modifier = modifiers[0]
    if modifier in {"contains", "startswith", "endswith"}:
        items = _normalize_scalar_list(value)
        if items is None:
            warnings.append(
                _warning(
                    code="unsupported_detection_value",
                    path=path,
                    message=f"Sigma {modifier} requires a scalar or a flat list of scalars.",
                    value=raw_value,
                )
            )
            return None
        normalized_value: Any
        normalized_value = [str(item) for item in items]
        if len(normalized_value) == 1:
            normalized_value = normalized_value[0]
        return f"{canonical_field}|{modifier}", normalized_value

    if modifier in {"gt", "gte", "lt", "lte"}:
        number = _coerce_numeric(value)
        if number is None:
            warnings.append(
                _warning(
                    code="unsupported_detection_value",
                    path=path,
                    message=f"Sigma {modifier} requires a numeric value.",
                    value=raw_value,
                )
            )
            return None
        return f"{canonical_field}|{modifier}", number

    if modifier == "exists":
        if not isinstance(value, bool):
            warnings.append(
                _warning(
                    code="unsupported_detection_value",
                    path=path,
                    message="Sigma exists requires a boolean value.",
                    value=raw_value,
                )
            )
            return None
        return f"{canonical_field}|exists", value

    if modifier == "neq":
        if isinstance(value, list):
            items = _normalize_scalar_list(value)
            if items is None:
                warnings.append(
                    _warning(
                        code="unsupported_detection_value",
                        path=path,
                        message="Sigma neq list values must contain only scalars.",
                        value=raw_value,
                    )
                )
                return None
            return f"{canonical_field}|not_in", items
        if isinstance(value, Mapping):
            warnings.append(
                _warning(
                    code="unsupported_detection_value",
                    path=path,
                    message="Sigma neq does not support mapping values.",
                    value=raw_value,
                )
            )
            return None
        return f"{canonical_field}|neq", value

    warnings.append(
        _warning(
            code="unsupported_detection_operator",
            path=path,
            message=f"Unsupported Sigma modifier: {modifier}",
            value=raw_value,
        )
    )
    return None


def _convert_selection(
    *,
    selection_name: str,
    raw_selection: Any,
    warnings: list[dict[str, Any]],
    blocked_selections: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(raw_selection, Mapping):
        warnings.append(
            _warning(
                code="unsupported_detection_selection",
                path=f"detection.{selection_name}",
                message="Sigma selections must be mappings in the supported subset.",
                value=raw_selection,
            )
        )
        blocked_selections[selection_name] = raw_selection
        return _blocked_selection(selection_name)

    converted: dict[str, Any] = {}
    for raw_key, raw_value in raw_selection.items():
        field_name, modifiers = _parse_sigma_field_key(ensure_non_empty_string(raw_key, field_name=f"detection.{selection_name} key"))
        canonical_field = _resolve_sigma_field(field_name)
        path = f"detection.{selection_name}.{raw_key}"
        if canonical_field is None:
            warnings.append(
                _warning(
                    code="unsupported_detection_field",
                    path=path,
                    message=f"Unsupported Sigma field for Seagull import: {field_name}",
                    value=raw_value,
                )
            )
            blocked_selections[selection_name] = raw_selection
            return _blocked_selection(selection_name)

        converted_predicate = _convert_predicate(
            canonical_field=canonical_field,
            modifiers=modifiers,
            raw_value=raw_value,
            path=path,
            warnings=warnings,
        )
        if converted_predicate is None:
            blocked_selections[selection_name] = raw_selection
            return _blocked_selection(selection_name)

        predicate_key, predicate_value = converted_predicate
        if predicate_key in converted:
            warnings.append(
                _warning(
                    code="unsupported_detection_selection",
                    path=path,
                    message=f"Multiple Sigma predicates collapsed into the same Seagull field: {predicate_key}",
                    value=raw_selection,
                )
            )
            blocked_selections[selection_name] = raw_selection
            return _blocked_selection(selection_name)
        converted[predicate_key] = predicate_value

    if not converted:
        warnings.append(
            _warning(
                code="unsupported_detection_selection",
                path=f"detection.{selection_name}",
                message="Sigma selections must contain at least one supported predicate.",
                value=raw_selection,
            )
        )
        blocked_selections[selection_name] = raw_selection
        return _blocked_selection(selection_name)

    return converted


def _convert_timeframe(raw_timeframe: Any, warnings: list[dict[str, Any]]) -> str:
    if raw_timeframe is None:
        return DEFAULT_SIGMA_IMPORT_WINDOW
    text = str(raw_timeframe or "").strip()
    if text and _WINDOW_RE.fullmatch(text):
        return text
    warnings.append(
        _warning(
            code="unsupported_timeframe",
            path="detection.timeframe",
            message="Unsupported Sigma timeframe; falling back to Seagull's default import window.",
            value=raw_timeframe,
        )
    )
    return DEFAULT_SIGMA_IMPORT_WINDOW


def _convert_attack_tags(tags: list[str], warnings: list[dict[str, Any]]) -> dict[str, Any]:
    tactics: list[str] = []
    techniques: list[str] = []

    for tag in tags:
        lowered = str(tag or "").strip().lower()
        if not lowered.startswith("attack."):
            continue
        suffix = lowered.split(".", 1)[1]
        if suffix in _ATTACK_TACTICS and suffix not in tactics:
            tactics.append(suffix)
            continue
        if re.fullmatch(r"t\d{4}(?:\.\d{3})?", suffix, re.IGNORECASE):
            technique_id = suffix.upper()
            if technique_id not in techniques:
                techniques.append(technique_id)

    if len(tactics) > 1:
        warnings.append(
            _warning(
                code="multiple_attack_tactics",
                path="tags",
                message="Multiple ATT&CK tactics were present; only the first tactic was mapped.",
                value=tactics,
                blocking=False,
            )
        )
    if len(techniques) > 1:
        warnings.append(
            _warning(
                code="multiple_attack_techniques",
                path="tags",
                message="Multiple ATT&CK techniques were present; only the first technique was mapped.",
                value=techniques,
                blocking=False,
            )
        )

    attack: dict[str, Any] = {}
    if tactics:
        attack["tactic"] = tactics[0]
    if techniques:
        attack["technique_id"] = techniques[0]
        technique_name = _ATTACK_TECHNIQUE_NAMES.get(techniques[0])
        if technique_name:
            attack["technique"] = technique_name
    return attack


def _infer_event_type(converted_detection: Mapping[str, Any]) -> str | None:
    event_types: set[str] = set()
    for selection_name, selection in converted_detection.items():
        if selection_name == "condition" or not isinstance(selection, Mapping):
            continue
        value = selection.get("event.type")
        if isinstance(value, str) and value and not value.startswith(_BLOCKED_SELECTION_EVENT_TYPE_PREFIX):
            event_types.add(value)
    if len(event_types) == 1:
        return next(iter(event_types))
    return None


def _convert_detection(
    sigma_detection: Mapping[str, Any],
    warnings: list[dict[str, Any]],
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    selection_items = [(key, value) for key, value in sigma_detection.items() if key not in _SUPPORTED_SIGMA_DETECTION_META_FIELDS]
    if not selection_items:
        raise DetectionRuleValidationError("Sigma detection must contain at least one selection")

    raw_condition = ensure_non_empty_string(sigma_detection.get("condition"), field_name="Sigma detection condition")
    selection_name_map: dict[str, str] = {}
    converted_detection: dict[str, Any] = {}
    blocked_selections: dict[str, Any] = {}
    used_names: set[str] = set()

    for index, (original_name, raw_selection) in enumerate(selection_items, start=1):
        normalized_name = _normalize_selection_name(str(original_name), index=index)
        while normalized_name in used_names:
            normalized_name = f"{normalized_name}_{index}"
        used_names.add(normalized_name)
        selection_name_map[str(original_name)] = normalized_name
        if normalized_name != original_name:
            warnings.append(
                _warning(
                    code="selection_name_normalized",
                    path=f"detection.{original_name}",
                    message=f"Normalized Sigma selection name '{original_name}' to '{normalized_name}'.",
                    blocking=False,
                )
            )
        converted_detection[normalized_name] = _convert_selection(
            selection_name=normalized_name,
            raw_selection=raw_selection,
            warnings=warnings,
            blocked_selections=blocked_selections,
        )

    converted_condition = _rewrite_condition_for_seagull(raw_condition, selection_name_map)
    converted_detection["condition"] = converted_condition
    window = _convert_timeframe(sigma_detection.get("timeframe"), warnings)
    return converted_detection, window, blocked_selections


def _convert_sigma_status(sigma_status: Any) -> str | None:
    text = str(sigma_status or "").strip().lower()
    return text or None


def _convert_sigma_severity(level: Any, warnings: list[dict[str, Any]]) -> str:
    normalized_level = str(level or "").strip().lower()
    if not normalized_level:
        return "medium"
    severity = _SIGMA_LEVEL_TO_SEAGULL_SEVERITY.get(normalized_level)
    if severity:
        if normalized_level == "informational":
            warnings.append(
                _warning(
                    code="level_normalized",
                    path="level",
                    message="Sigma level 'informational' was normalized to Seagull severity 'low'.",
                    value=level,
                    blocking=False,
                )
            )
        return severity

    warnings.append(
        _warning(
            code="unsupported_level",
            path="level",
            message="Unsupported Sigma level; defaulting to Seagull severity 'medium'.",
            value=level,
        )
    )
    return "medium"


def import_sigma_rule_document(raw_rule: Mapping[str, Any], *, strict: bool = False) -> dict[str, Any]:
    sigma_rule = dict(ensure_mapping(raw_rule, field_name="Sigma rule"))
    title = ensure_non_empty_string(sigma_rule.get("title"), field_name="Sigma title")
    sigma_logsource = ensure_mapping(sigma_rule.get("logsource"), field_name="Sigma logsource")
    sigma_detection = ensure_mapping(sigma_rule.get("detection"), field_name="Sigma detection")

    if not any(str(sigma_logsource.get(field) or "").strip() for field in _SUPPORTED_SIGMA_LOGSOURCE_FIELDS):
        raise DetectionRuleValidationError("Sigma logsource must define at least one of category, product, or service")

    warnings: list[dict[str, Any]] = []
    unsupported_top_level: dict[str, Any] = {}
    unsupported_logsource: dict[str, Any] = {}

    for key, value in sigma_rule.items():
        if key not in _SUPPORTED_SIGMA_TOP_LEVEL_FIELDS:
            warnings.append(
                _warning(
                    code="unsupported_field",
                    path=key,
                    message=f"Unsupported Sigma top-level field: {key}",
                    value=value,
                )
            )
            unsupported_top_level[key] = value

    for key, value in sigma_logsource.items():
        if key not in _SUPPORTED_SIGMA_LOGSOURCE_FIELDS:
            warnings.append(
                _warning(
                    code="unsupported_logsource_field",
                    path=f"logsource.{key}",
                    message=f"Unsupported Sigma logsource field: {key}",
                    value=value,
                )
            )
            unsupported_logsource[key] = value

    converted_detection, converted_window, blocked_selections = _convert_detection(sigma_detection, warnings)
    tags = _normalize_string_items(sigma_rule.get("tags"))
    references = _normalize_string_items(sigma_rule.get("references"))
    false_positives = _normalize_string_items(sigma_rule.get("falsepositives"))
    attack = _convert_attack_tags(tags, warnings)
    logsource = {key: str(value).strip() for key, value in sigma_logsource.items() if key in _SUPPORTED_SIGMA_LOGSOURCE_FIELDS and str(value).strip()}
    inferred_event_type = _infer_event_type(converted_detection)
    if inferred_event_type:
        logsource["event_type"] = inferred_event_type

    rule: dict[str, Any] = {
        "schema_version": V2_RULE_SCHEMA_VERSION,
        "id": _derive_rule_id(sigma_rule),
        "name": title,
        "description": str(sigma_rule.get("description") or "").strip() or None,
        "enabled": False,
        "status": "disabled",
        "maturity": "experimental",
        "severity": _convert_sigma_severity(sigma_rule.get("level"), warnings),
        "logsource": logsource,
        "attack": attack,
        "detection": converted_detection,
        "aggregation": {
            "type": "threshold",
            "window": converted_window,
            "condition": {"operator": ">=", "value": 1},
            "min_events": 1,
        },
        "suppression": {
            "cooldown": DEFAULT_SIGMA_IMPORT_COOLDOWN,
            "rules": [],
        },
        "tuning": {},
        "response": {},
        "tags": tags,
        "references": references,
        "sigma_status": _convert_sigma_status(sigma_rule.get("status")),
        "sigma_import": {
            "source": "sigma",
            "original_id": str(sigma_rule.get("id") or "").strip() or None,
            "original_status": _convert_sigma_status(sigma_rule.get("status")),
            "original_level": str(sigma_rule.get("level") or "").strip() or None,
            "warning_count": len(warnings),
            "warnings": warnings,
        },
    }

    if false_positives:
        rule["response"]["false_positives"] = false_positives
    if unsupported_top_level:
        rule["sigma_import"]["unsupported_top_level_fields"] = unsupported_top_level
    if unsupported_logsource:
        rule["sigma_import"]["unsupported_logsource_fields"] = unsupported_logsource
    if blocked_selections:
        rule["sigma_import"]["blocked_selections"] = blocked_selections

    blocking_warnings = [warning for warning in warnings if warning.get("blocking")]
    rule["sigma_import"]["blocking_warning_count"] = len(blocking_warnings)

    if strict and blocking_warnings:
        raise DetectionRuleValidationError(
            "Sigma import rejected in strict mode: "
            + "; ".join(
                f"{warning.get('path')}: {warning.get('message')}"
                for warning in blocking_warnings
            )
        )

    validate_rule_document(rule)
    return {
        "rule": rule,
        "warnings": warnings,
        "warning_count": len(warnings),
        "blocking_warning_count": len(blocking_warnings),
        "supported": len(blocking_warnings) == 0,
    }


def import_sigma_yaml(raw_yaml: str, *, strict: bool = False) -> dict[str, Any]:
    data = yaml.safe_load(raw_yaml) or {}
    if not isinstance(data, Mapping):
        raise DetectionRuleValidationError("Sigma YAML must contain a single mapping document")
    return import_sigma_rule_document(data, strict=strict)


def load_sigma_rule_file(path: str | Path) -> dict[str, Any]:
    sigma_path = Path(path).resolve()
    with sigma_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, Mapping):
        raise DetectionRuleValidationError(f"Sigma file must contain a mapping document: {sigma_path}")
    return dict(data)


def build_sigma_import_pack_document(
    rule: Mapping[str, Any],
    *,
    pack: str = DEFAULT_SIGMA_IMPORT_PACK,
    category: str | None = None,
) -> dict[str, Any]:
    logsource = rule.get("logsource") if isinstance(rule.get("logsource"), Mapping) else {}
    resolved_category = category or str(logsource.get("category") or DEFAULT_SIGMA_IMPORT_CATEGORY)
    return {
        "schema_version": V2_RULE_SCHEMA_VERSION,
        "pack": _coerce_pack_token(pack, default=DEFAULT_SIGMA_IMPORT_PACK),
        "category": _coerce_pack_token(resolved_category, default=DEFAULT_SIGMA_IMPORT_CATEGORY),
        "pack_version": 1,
        "maturity": "experimental",
        "rules": [dict(rule)],
    }


def convert_sigma_file(
    input_path: str | Path,
    output_path: str | Path,
    *,
    strict: bool = False,
    pack: str = DEFAULT_SIGMA_IMPORT_PACK,
    category: str | None = None,
) -> dict[str, Any]:
    sigma_rule = load_sigma_rule_file(input_path)
    result = import_sigma_rule_document(sigma_rule, strict=strict)
    output_file = Path(output_path).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    pack_document = build_sigma_import_pack_document(result["rule"], pack=pack, category=category)
    with output_file.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(pack_document, handle, sort_keys=False, allow_unicode=False)
    return {
        "input_file": str(Path(input_path).resolve()),
        "output_file": str(output_file),
        **result,
    }


def _iter_sigma_input_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path.resolve()]
    files: list[Path] = []
    for suffix in (".yml", ".yaml"):
        files.extend(path.resolve() for path in input_path.rglob(f"*{suffix}") if path.is_file())
    return sorted(set(files))


def convert_sigma_path(
    input_path: str | Path,
    output_path: str | Path,
    *,
    strict: bool = False,
    pack: str = DEFAULT_SIGMA_IMPORT_PACK,
    category: str | None = None,
) -> list[dict[str, Any]]:
    source = Path(input_path).resolve()
    target = Path(output_path).resolve()

    if not source.exists():
        raise DetectionRuleValidationError(f"Sigma input path does not exist: {source}")

    if source.is_file():
        return [convert_sigma_file(source, target, strict=strict, pack=pack, category=category)]

    files = _iter_sigma_input_files(source)
    results: list[dict[str, Any]] = []
    for sigma_file in files:
        relative_path = sigma_file.relative_to(source)
        destination = target / relative_path
        results.append(convert_sigma_file(sigma_file, destination, strict=strict, pack=pack, category=category))
    return results


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert a safe subset of Sigma YAML into Seagull v2 rule packs.")
    parser.add_argument("--input", required=True, help="Sigma YAML file or directory to import.")
    parser.add_argument("--output", required=True, help="Destination Seagull YAML file or directory.")
    parser.add_argument("--strict", action="store_true", help="Reject any import that produces blocking warnings.")
    parser.add_argument("--pack", default=DEFAULT_SIGMA_IMPORT_PACK, help="Pack name for generated Seagull YAML.")
    parser.add_argument("--category", default=None, help="Category for generated Seagull YAML.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    results = convert_sigma_path(
        args.input,
        args.output,
        strict=bool(args.strict),
        pack=str(args.pack or DEFAULT_SIGMA_IMPORT_PACK),
        category=args.category,
    )

    converted = len(results)
    total_warnings = sum(int(result.get("warning_count") or 0) for result in results)
    print(f"Converted {converted} Sigma file(s) into Seagull v2 YAML.")
    for result in results:
        warning_count = int(result.get("warning_count") or 0)
        print(f"- {result['input_file']} -> {result['output_file']} ({warning_count} warning(s))")
    if total_warnings:
        print(f"Total warnings: {total_warnings}")
    return 0


__all__ = [
    "DEFAULT_SIGMA_IMPORT_CATEGORY",
    "DEFAULT_SIGMA_IMPORT_PACK",
    "build_sigma_import_pack_document",
    "convert_sigma_file",
    "convert_sigma_path",
    "import_sigma_rule_document",
    "import_sigma_yaml",
    "load_sigma_rule_file",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
