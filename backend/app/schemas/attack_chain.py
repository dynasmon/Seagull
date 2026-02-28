from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.mitre import MitreCaseSummary


class AttackChainAllowlistDB(BaseModel):
    id: int
    rule_type: str
    enabled: bool
    match_mode: str
    pattern: str

    agent_id: Optional[str] = None
    username: Optional[str] = None
    target_user: Optional[str] = None
    notes: Optional[str] = None

    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AttackChainAllowlistCreate(BaseModel):
    enabled: bool = True
    match_mode: str = Field("contains", description="exact | prefix | contains")
    pattern: str = Field(..., min_length=1, max_length=512)
    agent_id: Optional[str] = Field(None, min_length=1, max_length=64)
    username: Optional[str] = Field(None, min_length=1, max_length=128)
    target_user: Optional[str] = Field(None, min_length=1, max_length=128)
    notes: Optional[str] = Field(None, max_length=256)


class AttackChainAllowlistUpdate(BaseModel):
    enabled: Optional[bool] = None
    match_mode: Optional[str] = Field(None, description="exact | prefix | contains")
    pattern: Optional[str] = Field(None, min_length=1, max_length=512)
    agent_id: Optional[str] = Field(None, min_length=1, max_length=64)
    username: Optional[str] = Field(None, min_length=1, max_length=128)
    target_user: Optional[str] = Field(None, min_length=1, max_length=128)
    notes: Optional[str] = Field(None, max_length=256)


class AttackChainCaseDB(BaseModel):
    id: int
    agent_id: str
    suspect_ip: Optional[str] = None

    status: str
    score: int
    max_stage: str

    first_seen_at: datetime
    last_seen_at: datetime
    closed_at: Optional[datetime] = None

    step_count: int
    context: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class AttackChainStepDB(BaseModel):
    id: int
    case_id: int
    stage: str
    label: str
    score_delta: int

    fingerprint: str

    event_id: Optional[int] = None
    event_type: Optional[str] = None

    timestamp: datetime
    created_at: datetime

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None

    details: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class AttackChainCaseWithSteps(BaseModel):
    case: AttackChainCaseDB
    steps: List[AttackChainStepDB]
