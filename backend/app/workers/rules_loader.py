import os
from pathlib import Path
from typing import Any, Dict, List

import yaml


RULES_DIR = Path(os.getenv("NETWATCH_RULES_DIR", "/app/rules"))


def load_rules() -> List[Dict[str, Any]]:
    """
    Load all rules from YAML files under RULES_DIR.
    Currently supports a single baseline.yml file, but can be extended.
    """
    rules: List[Dict[str, Any]] = []

    if not RULES_DIR.exists():
        return rules

    for path in RULES_DIR.glob("*.yml"):
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            file_rules = data.get("rules", [])
            for rule in file_rules:
                if rule.get("enabled", True):
                    rules.append(rule)

    return rules
