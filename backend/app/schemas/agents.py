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
    agent_token: Optional[str] = None
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


class AgentBootstrapTokenCreateIn(BaseModel):
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=86400)
    max_uses: Optional[int] = Field(default=None, ge=1, le=100)
    description: Optional[str] = Field(default=None, max_length=256)


class AgentBootstrapTokenOut(BaseModel):
    agent_id: str
    bootstrap_token: str
    expires_at: datetime
    max_uses: int


class AgentIdentityPublic(BaseModel):
    id: int
    agent_id: str
    fingerprint_sha256: str
    serial_number: str
    subject_dn: str
    issuer_dn: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_revoked: bool
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None
    created_at: datetime
    last_seen_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentIdentityRevokeIn(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=256)
