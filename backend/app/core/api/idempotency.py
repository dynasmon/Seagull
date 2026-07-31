from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Dict, Optional

from fastapi import HTTPException, Request, status

from app.core.cache.client import get_redis
from app.core.observability import incr_counter

BATCH_ID_HEADER = "X-Seagull-Batch-Id"
DEFAULT_TTL_SECONDS = 48 * 60 * 60
PROCESSING_TTL_SECONDS = 15 * 60
MAX_BATCH_ID_LENGTH = 128
MAX_RESULT_BYTES = 64 * 1024
_BATCH_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def read_batch_id(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    raw = (request.headers.get(BATCH_ID_HEADER) or "").strip()
    if not raw:
        return None
    if len(raw) > MAX_BATCH_ID_LENGTH or not _BATCH_ID_RE.fullmatch(raw):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_batch_id", "message": f"{BATCH_ID_HEADER} has an invalid format"},
        )
    return raw


def request_fingerprint(value: Any) -> str:
    payload = json.dumps(
        _json_value(value),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _json_value(value.model_dump(mode="json"))
    if hasattr(value, "dict"):
        return _json_value(value.dict())
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _key(scope: str, agent_id: str, batch_id: str) -> str:
    return f"idem:{scope}:{agent_id}:{batch_id}"


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"error": "idempotency_unavailable", "message": "durable batch admission is unavailable"},
        headers={"Retry-After": "1"},
    )


def run_once(
    *,
    scope: str,
    agent_id: str,
    batch_id: Optional[str],
    handler: Callable[[], Any],
    request_digest: Optional[str] = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> Any:
    if not batch_id:
        return handler()

    key = _key(scope, agent_id, batch_id)
    digest = str(request_digest or "")
    client = get_redis()
    if client is None:
        raise _unavailable()

    processing = json.dumps(
        {"state": "processing", "digest": digest},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    try:
        claimed = bool(client.set(key, processing, nx=True, ex=PROCESSING_TTL_SECONDS))
    except Exception as exc:
        raise _unavailable() from exc

    if not claimed:
        record = _load_record(client, key)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_425_TOO_EARLY,
                detail={"error": "batch_in_flight", "message": "batch result is not durable yet"},
                headers={"Retry-After": "1"},
            )
        stored_digest = str(record.get("digest") or "")
        if digest and stored_digest and digest != stored_digest:
            incr_counter("agent_ingest_batch_conflict_total", scope=scope)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "batch_payload_conflict", "message": "batch id was reused with different content"},
            )
        if record.get("state") != "completed":
            raise HTTPException(
                status_code=status.HTTP_425_TOO_EARLY,
                detail={"error": "batch_in_flight", "message": "batch result is not durable yet"},
                headers={"Retry-After": "1"},
            )
        result = record.get("result")
        if not isinstance(result, dict):
            raise _unavailable()
        incr_counter("agent_ingest_duplicate_batch_total", scope=scope)
        return {**result, "duplicate": True}

    try:
        result = handler()
    except Exception:
        try:
            client.delete(key)
        except Exception:
            pass
        raise

    normalized = _result_mapping(result)
    _store_result(client, key, digest, normalized, ttl_seconds)
    return result


def _load_record(client, key: str) -> Optional[Dict[str, Any]]:
    try:
        raw = client.get(key)
    except Exception as exc:
        raise _unavailable() from exc
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise _unavailable() from exc
    if not isinstance(value, dict):
        raise _unavailable()
    if "state" not in value:
        return {"state": "completed", "digest": "", "result": value}
    return value


def _result_mapping(result: Any) -> Dict[str, Any]:
    value = _json_value(result)
    if not isinstance(value, dict):
        raise RuntimeError("idempotent handlers must return an object")
    return value


def _store_result(client, key: str, digest: str, result: Dict[str, Any], ttl_seconds: int) -> None:
    payload = json.dumps(
        {"state": "completed", "digest": digest, "result": result},
        ensure_ascii=True,
        separators=(",", ":"),
        default=str,
    )
    if len(payload.encode("utf-8")) > MAX_RESULT_BYTES:
        raise _unavailable()
    try:
        stored = client.setex(key, int(ttl_seconds), payload)
    except Exception as exc:
        raise _unavailable() from exc
    if stored is False:
        raise _unavailable()
