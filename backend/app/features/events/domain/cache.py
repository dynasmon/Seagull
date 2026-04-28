from __future__ import annotations

import json
from typing import Any, Dict, Optional

from app.core.redis_client import get_redis


def _cache_get_json(key: str) -> Optional[Dict[str, Any]]:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        if not raw:
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _cache_set_json(key: str, payload: Dict[str, Any], ttl_s: int) -> None:
    if ttl_s <= 0:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(key, int(ttl_s), json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
    except Exception:
        return


def _cache_delete_prefixes(*prefixes: str) -> None:
    r = get_redis()
    if r is None:
        return
    for prefix in prefixes:
        raw_prefix = str(prefix or "").strip()
        if not raw_prefix:
            continue
        try:
            cursor: int | str = 0
            while True:
                cursor, keys = r.scan(cursor=cursor, match=f"{raw_prefix}*", count=200)
                if keys:
                    r.delete(*keys)
                if str(cursor) == "0":
                    break
        except Exception:
            return


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
                    f"seagull:events:ssh_summary:v3:sm=",
                    f"seagull:events:network_summary:v4:",
                ]
            )
    _cache_delete_prefixes(*prefixes)
