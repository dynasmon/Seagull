from sqlalchemy import Column, DateTime, Integer, String, func, SmallInteger
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AgentInventorySnapshotModel(Base):
    __tablename__ = "agent_inventory_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), index=True, nullable=False)

    collected_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    schema_version = Column(SmallInteger, nullable=False, default=1)

    os = Column(JSONB, nullable=False, default=dict)
    packages = Column(JSONB, nullable=False, default=list)

    packages_hash = Column(String(64), nullable=False)
    packages_count = Column(Integer, nullable=False, default=0)
    manager = Column(String(32), nullable=True)

    extra = Column(JSONB, nullable=False, default=dict)


class AgentInventoryLatestModel(Base):
    __tablename__ = "agent_inventory_latest"

    agent_id = Column(String(64), primary_key=True, nullable=False)
    snapshot_id = Column(Integer, nullable=False)
    collected_at = Column(DateTime(timezone=True), nullable=False)

    os = Column(JSONB, nullable=False, default=dict)
    packages_count = Column(Integer, nullable=False, default=0)
    packages_hash = Column(String(64), nullable=False)
    manager = Column(String(32), nullable=True)
    extra = Column(JSONB, nullable=False, default=dict)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
