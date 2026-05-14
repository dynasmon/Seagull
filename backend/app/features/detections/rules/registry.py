from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.features.detections.domain.canonical_fields import CANONICAL_FIELD_MAP, resolve_canonical_field
from app.features.detections.domain.operators import (
    DEFAULT_FIELD_OPERATOR,
    join_operator_suffix,
    split_operator_suffix,
)
from app.features.detections.domain.validation import DetectionRuleValidationError, ensure_field_operator

SUPPORTED_RUNTIME_EVENT_FIELDS = frozenset(
    {
        "agent_id",
        "event_type",
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "proto",
        "bytes",
        "app_proto",
        "app_proto_reason",
        "app_proto_conf_band",
        "dns_qname",
        "http_host",
        "http_method",
        "tls_sni",
        "tls_alpn_first",
        "ja3",
        "ja4",
        "ja4_ptype",
        "ssh_action",
        "ssh_username",
        "proc_pid",
        "proc_ppid",
        "proc_name",
        "proc_exe",
        "proc_parent_name",
        "fim_path",
        "fim_category",
        "heuristic_name",
        "heuristic_confidence",
    }
)

_EXPLICIT_JSONB_RUNTIME_FIELDS = frozenset(
    spec.model_attr
    for spec in CANONICAL_FIELD_MAP.values()
    if spec.storage_kind == "jsonb"
)


def is_legacy_extra_match_key(raw_key: str) -> bool:
    return str(raw_key or "").strip().startswith("extra_")


def resolve_runtime_field(field_name: str) -> str:
    key = str(field_name or "").strip()
    if not key:
        raise DetectionRuleValidationError("Field name cannot be empty")
    if key in SUPPORTED_RUNTIME_EVENT_FIELDS:
        return key
    if key in CANONICAL_FIELD_MAP:
        return resolve_canonical_field(key).model_attr
    if key in _EXPLICIT_JSONB_RUNTIME_FIELDS:
        return key
    raise DetectionRuleValidationError(f"Unsupported detection field: {key}")


def normalize_match_fields(match: Mapping[str, Any] | None) -> dict[str, Any]:
    if match is None:
        return {}
    if not isinstance(match, Mapping):
        raise DetectionRuleValidationError("match must be a mapping")

    normalized: dict[str, Any] = {}
    for raw_key, value in match.items():
        key = str(raw_key or "").strip()
        if not key:
            raise DetectionRuleValidationError("match contains an empty field name")
        if is_legacy_extra_match_key(key):
            normalized[key] = value
            continue

        base_field, operator = split_operator_suffix(key)
        ensure_field_operator(operator)
        runtime_field = resolve_runtime_field(base_field)
        normalized_key = join_operator_suffix(runtime_field, operator or DEFAULT_FIELD_OPERATOR)
        normalized[normalized_key] = value

    return normalized


def normalize_group_by_fields(group_by: str | list[str] | tuple[str, ...] | None) -> str | list[str] | None:
    if group_by is None:
        return None
    if isinstance(group_by, str):
        return resolve_runtime_field(group_by)
    if not isinstance(group_by, (list, tuple)):
        raise DetectionRuleValidationError("group_by must be a string or list of strings")
    return [resolve_runtime_field(field_name) for field_name in group_by]
