from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

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
    batch_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    requested_by: str
    requested_at: datetime
    delivered_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    cancelled_by: Optional[str] = None
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ResponseActionResultOut(BaseModel):
    id: int
    response_action_id: int
    agent_id: str
    status: str
    result_payload: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AgentResponseActionOut(BaseModel):
    id: int
    action_type: str
    agent_id: str
    status: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    requested_at: datetime
    expires_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AgentResponseActionResultIn(BaseModel):
    response_action_id: int = Field(..., ge=1)
    agent_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    status: str = Field(..., min_length=1, max_length=16)
    result_payload: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = Field(default=None, max_length=4000)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @validator("status", pre=True)
    def _v_status(cls, v):
        s = str(v or "").strip().lower()
        if s not in {"running", "success", "failed"}:
            raise ValueError("status is invalid")
        return s

    @validator("agent_id", pre=True)
    def _v_agent_id(cls, v):
        if v is None:
            return None
        s = str(v).strip()
        return s or None


class ActionTypeOut(BaseModel):
    key: str
    label: str
    category: str
    risk_level: str
    reversible: bool
    requires_confirmation: bool
    estimated_duration_seconds: int
    undo_action: Optional[str] = None
    description: str


class BatchDispatchIn(BaseModel):
    action_type: str = Field(..., min_length=1, max_length=32)
    agent_ids: List[str] = Field(default_factory=list)
    payload: Dict[str, Any] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None

    @validator("action_type", pre=True)
    def _v_action_type(cls, v):
        s = str(v or "").strip().lower()
        if not s:
            raise ValueError("action_type is required")
        return s


class BatchQueuedItem(BaseModel):
    agent_id: str
    action_id: int


class BatchSkippedItem(BaseModel):
    agent_id: str
    reason: str


class BatchDispatchOut(BaseModel):
    batch_id: str
    total: int
    queued: List[BatchQueuedItem] = Field(default_factory=list)
    skipped: List[BatchSkippedItem] = Field(default_factory=list)


class TimelineEventOut(BaseModel):
    at: datetime
    event: str
    actor: str
    detail: Optional[str] = None
