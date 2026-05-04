from __future__ import annotations

from datetime import datetime
from typing import Any

from app.features.detections.testing.yaml_tests import evaluate_detection_rule
from app.workers.intelligence.rules.loader import load_rules


def evaluate_rule(rule: dict[str, Any], events: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    return evaluate_detection_rule(rule, events, now)


def load_rule_index(rules_dir: str) -> dict[str, dict[str, Any]]:
    rules = load_rules(include_disabled=True, with_source=True, rules_dir=rules_dir, apply_env_filters=False)
    return {str(rule.get("id")): rule for rule in rules if rule.get("id")}
