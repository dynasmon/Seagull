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


from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AdminAuditEventOut(BaseModel):
    id: str
    operation_id: str | None = None
    created_at: datetime
    event_type: str
    action: str
    outcome: str
    actor_user_id: int | None = None
    actor_username: str | None = None
    resource_type: str
    resource_id: str | None = None
    request_id: str | None = None
    trace_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    method: str | None = None
    path: str | None = None
    reason: str | None = None
    error: str | None = None
    changed_fields: list[str] = Field(default_factory=list)
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    prev_event_hash: str | None = None
    event_hash: str | None = None


class AdminAuditQueryOut(BaseModel):
    items: list[AdminAuditEventOut]
    has_more: bool

