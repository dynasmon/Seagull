from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Literal

from pydantic import BaseModel, Field, validator

RealtimeMode = Literal["patch", "append", "replace", "invalidate"]


class RealtimeEnvelope(BaseModel):
    version: int = Field(2, ge=1, le=2)
    topic: str = Field(..., min_length=1, max_length=64)
    type: str = Field(..., min_length=1, max_length=128)
    cursor: str = Field(..., min_length=1, max_length=64)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scope: str = Field(..., min_length=1, max_length=128)
    mode: RealtimeMode = Field(...)
    payload: Dict[str, Any] = Field(default_factory=dict)

    @validator("topic", pre=True)
    def _v_topic(cls, v):
        value = str(v or "").strip().lower()
        if not value:
            raise ValueError("topic is required")
        return value

    @validator("type", pre=True)
    def _v_type(cls, v):
        value = str(v or "").strip()
        if not value:
            raise ValueError("type is required")
        return value

    @validator("cursor", pre=True)
    def _v_cursor(cls, v):
        value = str(v or "").strip()
        if not value:
            raise ValueError("cursor is required")
        if not value.isdigit():
            raise ValueError("cursor must be numeric")
        return value

    @validator("scope", pre=True)
    def _v_scope(cls, v):
        value = str(v or "").strip().lower()
        if not value:
            raise ValueError("scope is required")
        return value

    @validator("mode", pre=True)
    def _v_mode(cls, v):
        value = str(v or "").strip().lower()
        if value not in {"patch", "append", "replace", "invalidate"}:
            raise ValueError("mode is invalid")
        return value

    @validator("payload", pre=True)
    def _v_payload(cls, v):
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("payload must be an object")
        return v

    @validator("timestamp", pre=True, always=True)
    def _v_timestamp(cls, v):
        if v is None:
            return datetime.now(timezone.utc)
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        if isinstance(v, str):
            raw = v.strip()
            if not raw:
                return datetime.now(timezone.utc)
            if raw.endswith("Z"):
                raw = f"{raw[:-1]}+00:00"
            try:
                parsed = datetime.fromisoformat(raw)
            except ValueError as exc:
                raise ValueError("timestamp must be a valid ISO datetime") from exc
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        raise ValueError("timestamp must be a datetime")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": int(self.version),
            "topic": self.topic,
            "type": self.type,
            "cursor": self.cursor,
            "timestamp": self.timestamp.isoformat(),
            "scope": self.scope,
            "mode": self.mode,
            "payload": self.payload,
        }

    def as_json(self) -> str:
        try:
            return json.dumps(self.as_dict(), ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("payload must be JSON-serializable") from exc


class StreamTokenOut(BaseModel):
    stream_token: str
    token_type: str = "stream"
    expires_in: int = Field(..., ge=1, le=300)
