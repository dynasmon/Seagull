from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class DeadLetterMessageOut(BaseModel):
    position: int
    agent_id: str
    received: int
    retries: int
    received_at: Optional[str] = None
    mode: str
    storm_reason: str
    hot_events: int
    analytics_events: int
    warm_events: int
    rollups: int
    payload_bytes: int
    readable: bool


class DeadLetterPageOut(BaseModel):
    messages: int
    offset: int
    limit: int
    items: List[DeadLetterMessageOut] = Field(default_factory=list)


class DeadLetterRedriveOut(BaseModel):
    requeued_messages: int
    requeued_events: int
    skipped_messages: int
    remaining_messages: int


class DeadLetterPurgeOut(BaseModel):
    purged_messages: int
    remaining_messages: int
