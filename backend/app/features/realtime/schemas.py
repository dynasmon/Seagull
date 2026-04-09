from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

from pydantic import BaseModel, Field, validator


class RealtimeEnvelope(BaseModel):
    version: int = Field(1, ge=1, le=1)
    type: str = Field(..., min_length=1, max_length=128)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: Dict[str, Any] = Field(default_factory=dict)

    @validator("type", pre=True)
    def _v_type(cls, v):
        value = str(v or "").strip()
        if not value:
            raise ValueError("type is required")
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
        raise ValueError("timestamp must be a datetime")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": int(self.version),
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
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
