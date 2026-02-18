from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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
