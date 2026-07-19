from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings
from app.features.detections.domain.rule_types import V1_RULE_SCHEMA_VERSION
from app.features.detections.domain.validation import DetectionRuleValidationError, normalize_string_list
from app.features.detections.rules.compatibility import normalize_rule_document, resolve_rule_schema_version
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


_YAML_SAFE_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

_rule_file_cache: dict[Path, tuple[int, int, dict[str, Any]]] = {}


def _load_rule_file(path: Path) -> dict[str, Any]:
    stat = path.stat()
    cached = _rule_file_cache.get(path)
    if cached is not None and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return copy.deepcopy(cached[2])
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.load(handle, Loader=_YAML_SAFE_LOADER) or {}
    if not isinstance(data, dict):
        raise DetectionRuleValidationError(f"Rule file must contain a mapping: {path}")
    _rule_file_cache[path] = (stat.st_mtime_ns, stat.st_size, data)
    return copy.deepcopy(data)


def _file_meta_from_document(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "pack": data.get("pack"),
        "category": data.get("category"),
        "maturity": data.get("maturity"),
        "environments": data.get("environments"),
        "pack_version": data.get("pack_version", 1),
        "schema_version": data.get("schema_version", 1),
    }


def _current_rules_env() -> str:
    return str(getattr(settings, "SEAGULL_RULES_ENV", getattr(settings, "SEAGULL_ENV", "dev")) or "dev").strip().lower()


def _should_include_rule(
    rule: dict[str, Any],
    *,
    include_disabled: bool,
    apply_env_filters: bool,
    env_name: str,
    enabled_packs: set[str],
    disabled_packs: set[str],
    include_experimental: bool,
) -> bool:
    if not include_disabled and rule.get("enabled", True) is False:
        return False

    if not apply_env_filters:
        return True

    pack = str(rule.get("pack") or "").strip().lower()
    maturity = str(rule.get("maturity") or "stable").strip().lower()
    envs = _norm_set(rule.get("environments") or [])

    if enabled_packs and pack and pack not in enabled_packs:
        return False
    if pack and pack in disabled_packs:
        return False
    if envs and env_name not in envs:
        return False
    if not include_experimental and maturity == "experimental":
        return False
    return True


def _build_error(
    *,
    source_file: str,
    message: str,
    rule_id: str | None = None,
    schema_version: int | None = None,
) -> dict[str, Any]:
    return {
        "source_file": source_file,
        "rule_id": rule_id,
        "schema_version": schema_version,
        "message": message,
    }


def _iter_rules_from_file(
    path: Path,
    rules_dir: Path,
    *,
    include_non_runtime: bool = True,
) -> list[dict[str, Any]]:
    data = _load_rule_file(path)
    file_rules = data.get("rules", [])
    if not isinstance(file_rules, list):
        raise DetectionRuleValidationError(f"Rule file rules must be a list: {path}")

    file_meta = _file_meta_from_document(data)
    source_file = str(path.relative_to(rules_dir))
    env_name = _current_rules_env()

    out: list[dict[str, Any]] = []
    for rule in file_rules:
        if not isinstance(rule, dict):
            continue
        schema_version = resolve_rule_schema_version(rule, file_meta)
        if not include_non_runtime and schema_version != V1_RULE_SCHEMA_VERSION:
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


def _run_inline_test_failures(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from app.features.detections.testing.yaml_tests import run_inline_rule_tests

    failures: list[dict[str, Any]] = []
    for rule in rules:
        if not rule.get("tests"):
            continue
        for result in run_inline_rule_tests(rule):
            if result.passed:
                continue
            failures.append(
                {
                    "rule_id": result.rule_id,
                    "test_id": result.test_id,
                    "expect": result.expect,
                    "outcome": result.outcome,
                    "failure_reason": result.failure_reason,
                }
            )
    return failures


def load_and_validate_rules(
    *,
    include_disabled: bool = True,
    with_source: bool = True,
    rules_dir: str | Path | None = None,
    apply_env_filters: bool = True,
    strict: bool = False,
    include_non_runtime: bool = True,
    execute_yaml_tests: bool = False,
) -> dict[str, Any]:
    out: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    base = _rules_dir_path(rules_dir)
    if not base.exists():
        report: dict[str, Any] = {"rules": out, "errors": errors}
        if execute_yaml_tests:
            report["inline_test_failures"] = []
        return report

    env_name = _current_rules_env()
    enabled_packs = _norm_set(getattr(settings, "SEAGULL_RULES_ENABLED_PACKS", []))
    disabled_packs = _norm_set(getattr(settings, "SEAGULL_RULES_DISABLED_PACKS", []))
    include_experimental = bool(getattr(settings, "SEAGULL_RULES_INCLUDE_EXPERIMENTAL", True))

    for path in _discover_rule_files(base):
        source_file = str(path.relative_to(base))
        try:
            rules = _iter_rules_from_file(path, base, include_non_runtime=include_non_runtime)
        except RuntimeError:
            raise
        except Exception as exc:
            error = _build_error(source_file=source_file, message=str(exc))
            if strict:
                raise DetectionRuleValidationError(error["message"]) from exc
            errors.append(error)
            continue

        for rule in rules:
            rule_id = str(rule.get("id") or "").strip() or None
            schema_version = int(rule.get("schema_version") or 1)
            if rule_id and rule_id in seen_ids:
                error = _build_error(
                    source_file=str(rule.get("source_file") or source_file),
                    rule_id=rule_id,
                    schema_version=schema_version,
                    message=f"Duplicate rule id detected: {rule_id}",
                )
                if strict:
                    raise RuntimeError(error["message"])
                errors.append(error)
                continue

            if not _should_include_rule(
                rule,
                include_disabled=include_disabled,
                apply_env_filters=apply_env_filters,
                env_name=env_name,
                enabled_packs=enabled_packs,
                disabled_packs=disabled_packs,
                include_experimental=include_experimental,
            ):
                if rule_id:
                    seen_ids.add(rule_id)
                continue

            if not with_source:
                rule = dict(rule)
                rule.pop("source_file", None)

            out.append(rule)
            if rule_id:
                seen_ids.add(rule_id)

    out.sort(key=lambda rule: (str(rule.get("pack") or ""), str(rule.get("category") or ""), str(rule.get("id") or "")))
    report = {"rules": out, "errors": errors}
    if execute_yaml_tests:
        report["inline_test_failures"] = _run_inline_test_failures(out)
    return report


def load_rules(
    *,
    include_disabled: bool = False,
    with_source: bool = False,
    rules_dir: str | Path | None = None,
    apply_env_filters: bool = True,
    include_non_runtime: bool = True,
) -> list[dict[str, Any]]:
    report = load_and_validate_rules(
        include_disabled=include_disabled,
        with_source=with_source,
        rules_dir=rules_dir,
        apply_env_filters=apply_env_filters,
        strict=True,
        include_non_runtime=include_non_runtime,
    )
    return list(report["rules"])
