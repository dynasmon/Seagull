from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, validator


class ResponseActionCreateIn(BaseModel):
    action_type: str = Field(..., min_length=1, max_length=32)
    agent_id: str = Field(..., min_length=1, max_length=64)
    payload: Dict[str, Any] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None

    @validator("action_type", pre=True)
    def _v_action_type(cls, v):
        s = str(v or "").strip().lower()
        if not s:
            raise ValueError("action_type is required")
        return s

    @validator("agent_id", pre=True)
    def _v_agent_id(cls, v):
        s = str(v or "").strip()
        if not s:
            raise ValueError("agent_id is required")
        return s


class ResponseActionOut(BaseModel):
    id: int
    action_type: str
    agent_id: str
    status: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    requested_by: str
    requested_at: datetime
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True
