"""Alert rule runtime adapter.

This module provides a feature-local import surface for rule execution and rule
composition helpers. It keeps `alerts.service` independent from direct imports
of worker implementation modules.
"""

from __future__ import annotations

from app.features.alerts.rule_registry_runtime import (
    apply_override,
    apply_tuning_and_suppressions,
    load_baseline_rules,
    normalize_rule_list,
)
from app.workers.rules_engine import run_all_rules

__all__ = [
    "apply_override",
    "apply_tuning_and_suppressions",
    "load_baseline_rules",
    "normalize_rule_list",
    "run_all_rules",
]
