from __future__ import annotations

import re
from typing import Any

from app.features.detections.domain.rule_types import (
    DEFAULT_RULE_SCHEMA_VERSION,
    SUPPORTED_RULE_SCHEMA_VERSIONS,
)
from app.features.detections.domain.validation import DetectionRuleValidationError, normalize_string_list
from app.features.detections.rules.registry import normalize_group_by_fields, normalize_match_fields


_VERSION_RE = re.compile(r"_v(\d+)$", re.IGNORECASE)


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

    normalized["pack"] = str(normalized.get("pack") or file_meta.get("pack") or "").strip() or None
    normalized["category"] = str(normalized.get("category") or file_meta.get("category") or "").strip() or None
    normalized["pack_version"] = int(file_meta.get("pack_version") or 1)
    normalized["rule_version"] = parse_rule_version(rule_id, normalized.get("version"))
    normalized["schema_version"] = schema_version
    normalized["maturity"] = (
        str(normalized.get("maturity") or file_meta.get("maturity") or "stable").strip().lower() or "stable"
    )
    normalized["environments"] = [env.lower() for env in normalize_string_list(normalized.get("environments", file_meta.get("environments")))]

    suppressions = normalized.get("suppressions")
    normalized["suppressions"] = suppressions if isinstance(suppressions, list) else []
    tuning = normalized.get("tuning")
    normalized["tuning"] = tuning if isinstance(tuning, dict) else {}

    if "match" in normalized:
        normalized["match"] = normalize_match_fields(normalized.get("match"))
    if "group_by" in normalized:
        normalized["group_by"] = normalize_group_by_fields(normalized.get("group_by"))

    if with_source:
        normalized["source_file"] = source_file
    return normalized
