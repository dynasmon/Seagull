"""Rule registry adapter for worker and feature callers.

This module exposes a stable alerts-owned contract for rule loading and rule
governance overlays. The current implementation delegates to existing worker
registry logic to preserve behavior.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.workers.intelligence.rules.registry import (
    apply_override,
    apply_tuning_and_suppressions,
    fetch_overrides,
    fetch_suppressions,
    fetch_tuning,
    load_baseline_rules,
    normalize_rule_list,
)


def prepare_effective_rules(db: Session) -> list[dict[str, Any]]:
    overrides = fetch_overrides(db)
    tunings = fetch_tuning(db)
    suppressions = fetch_suppressions(db)
    rules: list[dict[str, Any]] = []
    for base in normalize_rule_list(load_baseline_rules(include_disabled=True)):
        rid = base.get("id")
        eff, _ = apply_override(base, overrides.get(rid))
        eff = apply_tuning_and_suppressions(
            eff, tuning_row=tunings.get(str(rid)), suppression_rows=suppressions.get(str(rid)) or []
        )
        rules.append(eff)
    return rules


__all__ = [
    "apply_override",
    "apply_tuning_and_suppressions",
    "fetch_overrides",
    "fetch_suppressions",
    "fetch_tuning",
    "load_baseline_rules",
    "normalize_rule_list",
    "prepare_effective_rules",
]
