
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime
from typing import Any, Dict, Tuple

from fastapi import HTTPException

from app.core.config import settings


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    # urlsafe_b64decode requires padding.
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _hmac_sha256(payload: bytes, secret: str) -> bytes:
    key = (secret or "").encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).digest()


def encode_cursor(data: Dict[str, Any], secret: str | None = None) -> str:

    payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = _hmac_sha256(payload, secret or settings.token_pepper())
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def decode_cursor(token: str, secret: str | None = None) -> Dict[str, Any]:

    if not token or "." not in token:
        raise HTTPException(status_code=400, detail="Invalid cursor")

    try:
        p_b64, s_b64 = token.split(".", 1)
        payload = _b64url_decode(p_b64)
        sig = _b64url_decode(s_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor") from None

    expected = _hmac_sha256(payload, secret or settings.token_pepper())
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=400, detail="Invalid cursor")

    try:
        obj = json.loads(payload.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor") from None

    if not isinstance(obj, dict):
        raise HTTPException(status_code=400, detail="Invalid cursor")

    return obj


def parse_cursor_ts_id(token: str, *, ts_key: str = "ts", id_key: str = "id") -> Tuple[datetime, int]:

    obj = decode_cursor(token)
    ts_raw = obj.get(ts_key)
    id_raw = obj.get(id_key)

    if not isinstance(ts_raw, str) or not isinstance(id_raw, int):
        raise HTTPException(status_code=400, detail="Invalid cursor")

    try:
        ts = datetime.fromisoformat(ts_raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid cursor") from None

    return ts, int(id_raw)


def make_cursor_ts_id(ts: datetime, row_id: int, *, ts_key: str = "ts", id_key: str = "id") -> str:
    return encode_cursor({ts_key: ts.isoformat(), id_key: int(row_id)})
