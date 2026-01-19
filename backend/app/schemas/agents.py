from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AgentEnrollIn(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=64)
    hostname: Optional[str] = Field(default=None, max_length=255)
    os: Optional[str] = Field(default=None, max_length=128)
    version: Optional[str] = Field(default=None, max_length=64)


class AgentEnrollOut(BaseModel):
    agent_id: str
    agent_token: str
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentHeartbeatIn(BaseModel):
    status: str = Field(default="ok", max_length=32)
    uptime_seconds: Optional[int] = None
    modules: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None


class AgentConfigUpdateIn(BaseModel):
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentPublic(BaseModel):
    agent_id: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime
    last_seen_at: Optional[datetime]
    is_revoked: bool
    metadata: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class AgentDetail(AgentPublic):
    config: Dict[str, Any] = Field(default_factory=dict)


class AgentUpdateIn(BaseModel):
    display_name: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    tags: Optional[List[str]] = Field(default=None)
    metadata: Optional[Dict[str, Any]] = Field(default=None)
