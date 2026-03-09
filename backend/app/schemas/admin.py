from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class LoginEventOut(BaseModel):
    created_at: datetime
    username: str = Field(..., min_length=1, max_length=64)
    method: str = Field(..., min_length=1, max_length=16)
    ip: str | None = None
    user_agent: str | None = None
    succeeded: bool


class RuntimeConfigOut(BaseModel):
    config: dict[str, Any]
