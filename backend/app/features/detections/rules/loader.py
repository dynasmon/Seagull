from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings
from app.features.detections.domain.validation import normalize_string_list
from app.features.detections.rules.compatibility import normalize_rule_document
from app.features.detections.rules.validator import validate_rule_document


def _norm_set(values: Any) -> set[str]:
    return {value.lower() for value in normalize_string_list(values)}


def _rules_dir_path(rules_dir: str | Path | None = None) -> Path:
    if rules_dir is not None:
        return Path(rules_dir).resolve()
    return Path(getattr(settings, "SEAGULL_RULES_DIR", "/app/rules") or "/app/rules").resolve()


def _discover_rule_files(rules_dir: Path) -> list[Path]:
    files: list[Path] = []
    for suffix in (".yml", ".yaml"):
        files.extend(path for path in rules_dir.rglob(f"*{suffix}") if path.is_file())
    return [Path(path) for path in sorted({path.resolve() for path in files})]


def _iter_rules_from_file(path: Path, rules_dir: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        return []

    file_rules = data.get("rules", [])
    if not isinstance(file_rules, list):
        return []

    file_meta = {
        "pack": data.get("pack"),
        "category": data.get("category"),
        "maturity": data.get("maturity"),
        "environments": data.get("environments"),
        "pack_version": data.get("pack_version", 1),
        "schema_version": data.get("schema_version", 1),
    }
    source_file = str(path.relative_to(rules_dir))
    env_name = str(
        getattr(settings, "SEAGULL_RULES_ENV", getattr(settings, "SEAGULL_ENV", "dev")) or "dev"
    ).strip().lower()

    out: list[dict[str, Any]] = []
    for rule in file_rules:
        if not isinstance(rule, dict):
            continue
        normalized = normalize_rule_document(
            raw_rule=rule,
            file_meta=file_meta,
            env_name=env_name,
            source_file=source_file,
            with_source=True,
        )
        if normalized is None:
            continue
        validate_rule_document(normalized)
        out.append(normalized)
    return out


def load_rules(
    *,
    include_disabled: bool = False,
    with_source: bool = False,
    rules_dir: str | Path | None = None,
    apply_env_filters: bool = True,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    base = _rules_dir_path(rules_dir)
    if not base.exists():
        return out

    env_name = str(getattr(settings, "SEAGULL_RULES_ENV", getattr(settings, "SEAGULL_ENV", "dev")) or "dev").strip().lower()
    enabled_packs = _norm_set(getattr(settings, "SEAGULL_RULES_ENABLED_PACKS", []))
    disabled_packs = _norm_set(getattr(settings, "SEAGULL_RULES_DISABLED_PACKS", []))
    include_experimental = bool(getattr(settings, "SEAGULL_RULES_INCLUDE_EXPERIMENTAL", True))

    for path in _discover_rule_files(base):
        for rule in _iter_rules_from_file(path, base):
            if not with_source:
                rule.pop("source_file", None)

            rule_id = str(rule.get("id") or "").strip()
            if not rule_id:
                continue
            if rule_id in seen_ids:
                raise RuntimeError(f"Duplicate rule id detected: {rule_id}")

            if not include_disabled and rule.get("enabled", True) is False:
                continue

            if apply_env_filters:
                pack = str(rule.get("pack") or "").strip().lower()
                maturity = str(rule.get("maturity") or "stable").strip().lower()
                envs = _norm_set(rule.get("environments") or [])

                if enabled_packs and pack and pack not in enabled_packs:
                    continue
                if pack and pack in disabled_packs:
                    continue
                if envs and env_name not in envs:
                    continue
                if not include_experimental and maturity == "experimental":
                    continue

            out.append(rule)
            seen_ids.add(rule_id)

    out.sort(key=lambda rule: (str(rule.get("pack") or ""), str(rule.get("category") or ""), str(rule.get("id") or "")))
    return out
