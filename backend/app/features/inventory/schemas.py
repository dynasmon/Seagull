from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class PackageEntry(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    version: str = Field(..., min_length=1, max_length=255)
    arch: Optional[str] = Field(default=None, max_length=64)


class InventorySnapshotIn(BaseModel):
    schema_version: int = Field(1, ge=1, le=16)
    collected_at: Optional[datetime] = None
    os: Dict[str, Any] = Field(default_factory=dict)
    packages: List[PackageEntry] = Field(default_factory=list)
    packages_hash: Optional[str] = Field(default=None, max_length=64)
    packages_count: Optional[int] = None
    manager: Optional[str] = Field(default=None, max_length=32)
    extra: Dict[str, Any] = Field(default_factory=dict)


class InventorySnapshotOut(BaseModel):
    id: int
    agent_id: str
    collected_at: datetime
    schema_version: int
    os: Dict[str, Any]
    packages: List[PackageEntry]
    packages_hash: str
    packages_count: int
    manager: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)
