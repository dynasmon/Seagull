from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class PlatformSettingOut(BaseModel):
    key: str
    value: Any
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    updated_by_user_id: Optional[int] = None
    updated_by_username: Optional[str] = None


class PlatformSettingUpsertIn(BaseModel):
    value: Any
    description: Optional[str] = Field(None, max_length=255)
    reason: Optional[str] = Field(None, max_length=255)

