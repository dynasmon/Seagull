from __future__ import annotations

from sqlalchemy import Column, DateTime, Float, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class DashboardSnapshotModel(Base):
    __tablename__ = "dashboard_snapshots"

    page = Column(String(64), primary_key=True)
    scope_key = Column(String(512), primary_key=True)
    schema_version = Column(Integer, nullable=False, default=1)
    payload = Column(JSONB, nullable=False, default=dict)
    computed_at = Column(DateTime(timezone=True), nullable=False)
    computed_ms = Column(Float, nullable=False, default=0.0)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
