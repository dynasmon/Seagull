from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class AdminUserOut(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None
    failed_login_count: int


class AdminUserCreateIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=12, max_length=256)
    role: str = Field("user", min_length=1, max_length=32)
    is_active: bool = True
    reason: Optional[str] = Field(None, max_length=255)


class AdminUserUpdateIn(BaseModel):
    role: Optional[str] = Field(None, min_length=1, max_length=32)
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=12, max_length=256)
    reason: Optional[str] = Field(None, max_length=255)

