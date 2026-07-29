from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, Optional

from fastapi import Request

from app.core.cache.client import get_redis
from app.core.observability import incr_counter

BATCH_ID_HEADER = "X-Seagull-Batch-Id"
DEFAULT_TTL_SECONDS = 3600
MAX_BATCH_ID_LENGTH = 128
_BATCH_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def read_batch_id(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    raw = (request.headers.get(BATCH_ID_HEADER) or "").strip()
    if not raw or len(raw) > MAX_BATCH_ID_LENGTH:
        return None
    if not _BATCH_ID_RE.match(raw):
        return None
    return raw


def _key(scope: str, agent_id: str, batch_id: str) -> str:
    return f"idem:{scope}:{agent_id}:{batch_id}"


def run_once(
    *,
    scope: str,
    agent_id: str,
    batch_id: Optional[str],
    handler: Callable[[], Any],
    duplicate_result: Optional[Dict[str, Any]] = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> Any:
    if not batch_id:
        return handler()

    key = _key(scope, agent_id, batch_id)
    client = get_redis()
    if client is None:
        return handler()

    try:
        claimed = bool(client.set(key, "", nx=True, ex=int(ttl_seconds)))
    except Exception:
        return handler()

    if not claimed:
        cached = _load_cached(client, key)
        incr_counter("agent_ingest_duplicate_batch_total", scope=scope)
        if cached is not None:
            return {**cached, "duplicate": True}
        return {**(duplicate_result or {}), "duplicate": True}

    try:
        result = handler()
    except Exception:
        try:
            client.delete(key)
        except Exception:
            pass
        raise

    _store_result(client, key, result, ttl_seconds)
    return result


def _load_cached(client, key: str) -> Optional[Dict[str, Any]]:
    try:
        raw = client.get(key)
    except Exception:
        return None
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _store_result(client, key: str, result: Any, ttl_seconds: int) -> None:
    if not isinstance(result, dict):
        return
    try:
        payload = json.dumps(result, ensure_ascii=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return
    if len(payload) > 8192:
        return
    try:
        client.setex(key, int(ttl_seconds), payload)
    except Exception:
        return
