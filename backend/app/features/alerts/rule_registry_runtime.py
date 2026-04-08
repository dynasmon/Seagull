"""Rule registry adapter for worker and feature callers.

This module exposes a stable alerts-owned contract for rule loading and rule
governance overlays. The current implementation delegates to existing worker
registry logic to preserve behavior.
"""

from __future__ import annotations

from app.workers.rules_registry import (
    apply_override,
    apply_tuning_and_suppressions,
    fetch_overrides,
    fetch_suppressions,
    fetch_tuning,
    load_baseline_rules,
    normalize_rule_list,
)

__all__ = [
    "apply_override",
    "apply_tuning_and_suppressions",
    "fetch_overrides",
    "fetch_suppressions",
    "fetch_tuning",
    "load_baseline_rules",
    "normalize_rule_list",
]
