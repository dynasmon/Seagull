import os
from pathlib import Path
from typing import Any, Dict, List

import yaml


RULES_DIR = Path(os.getenv("NETWATCH_RULES_DIR", "/app/rules"))


def load_rules(*, include_disabled: bool = False, with_source: bool = False) -> List[Dict[str, Any]]:
    """Load rules from YAML files under RULES_DIR.

    Args:
        include_disabled: when True, returns rules even when enabled=false.
        with_source: when True, adds a "source_file" field with the YAML file name.
    """
    rules: List[Dict[str, Any]] = []

    if not RULES_DIR.exists():
        return rules

    for path in sorted(RULES_DIR.glob("*.yml")):
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            file_rules = data.get("rules", [])
            for rule in file_rules:
                if not isinstance(rule, dict):
                    continue

                enabled = rule.get("enabled", True)
                if (not include_disabled) and (enabled is False):
                    continue

                r = dict(rule)
                if with_source:
                    r["source_file"] = path.name
                rules.append(r)

    return rules
