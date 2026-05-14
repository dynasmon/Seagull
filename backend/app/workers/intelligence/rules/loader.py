from __future__ import annotations

from pathlib import Path

from app.features.detections.rules.compatibility import (
    apply_env_overrides as _apply_env_overrides,
)
from app.features.detections.rules.compatibility import (
    deep_merge as _deep_merge,
)
from app.features.detections.rules.compatibility import (
    env_aliases as _env_aliases,
)
from app.features.detections.rules.compatibility import (
    parse_rule_version as _parse_rule_version,
)
from app.features.detections.rules.loader import (
    _discover_rule_files,
    _iter_rules_from_file,
    _norm_set,
    _rules_dir_path,
)
from app.features.detections.rules.loader import (
    load_and_validate_rules as _load_and_validate_rules,
)
from app.features.detections.rules.loader import (
    load_rules as _load_rules,
)


def load_rules(
    *,
    include_disabled: bool = False,
    with_source: bool = False,
    rules_dir: str | Path | None = None,
    apply_env_filters: bool = True,
) -> list[dict]:
    return _load_rules(
        include_disabled=include_disabled,
        with_source=with_source,
        rules_dir=rules_dir,
        apply_env_filters=apply_env_filters,
        include_non_runtime=True,
    )


def load_and_validate_rules(
    *,
    include_disabled: bool = True,
    with_source: bool = True,
    rules_dir: str | Path | None = None,
    apply_env_filters: bool = True,
    strict: bool = False,
) -> dict:
    return _load_and_validate_rules(
        include_disabled=include_disabled,
        with_source=with_source,
        rules_dir=rules_dir,
        apply_env_filters=apply_env_filters,
        strict=strict,
        include_non_runtime=True,
    )

__all__ = [
    "_apply_env_overrides",
    "_deep_merge",
    "_discover_rule_files",
    "_env_aliases",
    "_iter_rules_from_file",
    "_norm_set",
    "_parse_rule_version",
    "_rules_dir_path",
    "load_and_validate_rules",
    "load_rules",
]
