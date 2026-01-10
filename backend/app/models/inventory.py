from sqlalchemy import Column, DateTime, Integer, JSON, String, func, SmallInteger

from app.core.db import Base


class AgentInventorySnapshotModel(Base):
    __tablename__ = "agent_inventory_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), index=True, nullable=False)

    collected_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    schema_version = Column(SmallInteger, nullable=False, default=1)

    os = Column(JSON, nullable=False, default=dict)
    packages = Column(JSON, nullable=False, default=list)

    packages_hash = Column(String(64), nullable=False)
    packages_count = Column(Integer, nullable=False, default=0)
    manager = Column(String(32), nullable=True)

    extra = Column(JSON, nullable=False, default=dict)
