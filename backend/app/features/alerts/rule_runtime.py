"""Alert rule runtime adapter.

This module provides a feature-local import surface for rule execution and rule
composition helpers. It keeps `alerts.service` independent from direct imports
of worker implementation modules.
"""

from __future__ import annotations

from app.workers.rules_engine import run_all_rules
from app.workers.rules_registry import (
    apply_override,
    apply_tuning_and_suppressions,
    load_baseline_rules,
    normalize_rule_list,
)

__all__ = [
    "apply_override",
    "apply_tuning_and_suppressions",
    "load_baseline_rules",
    "normalize_rule_list",
    "run_all_rules",
]
