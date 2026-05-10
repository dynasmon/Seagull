from __future__ import annotations

from typing import Any

from app.core.cache import delete_prefixes as _cache_delete_prefixes
from app.core.cache import get_json, set_json


def _cache_get_json(key: str) -> dict[str, Any] | None:
    return get_json(key)


def _cache_set_json(key: str, payload: dict[str, Any], ttl_s: int) -> None:
    set_json(key, payload, ttl_s)


def invalidate_live_event_summary_caches(*, agent_id: str | None = None) -> None:
    prefixes = [
        "seagull:events:ssh_summary:v3:",
        "seagull:events:network_summary:v4:",
    ]
    if agent_id:
        safe_agent_id = str(agent_id).strip()
        if safe_agent_id:
            prefixes.extend(
                [
                    "seagull:events:ssh_summary:v3:sm=",
                    "seagull:events:network_summary:v4:",
                ]
            )
    _cache_delete_prefixes(*prefixes)
