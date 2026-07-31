from __future__ import annotations

from typing import Any, Mapping


def revision(value: Any) -> int:
    if not isinstance(value, Mapping):
        return 0
    current = value.get("revision")
    if isinstance(current, bool) or not isinstance(current, int) or current < 1:
        return 0
    return current


def normalize(value: Any) -> dict[str, Any]:
    config = dict(value) if isinstance(value, Mapping) else {}
    if revision(config) == 0:
        config["revision"] = 1
    return config


def replace(current: Any, proposed: Any) -> dict[str, Any]:
    config = dict(proposed) if isinstance(proposed, Mapping) else {}
    config["revision"] = max(1, revision(current) + 1)
    return config
