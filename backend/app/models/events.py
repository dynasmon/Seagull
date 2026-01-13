from sqlalchemy import Column, DateTime, Integer, String, func, SmallInteger
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class NetEventModel(Base):
    __tablename__ = "net_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), index=True, nullable=False)
    event_type = Column(String(32), index=True, nullable=False)
    schema_version = Column(SmallInteger, nullable=False, default=1)
    timestamp = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())

    src_ip = Column(String(45), index=True, nullable=True)
    dst_ip = Column(String(45), index=True, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    proto = Column(String(16), nullable=True)
    bytes = Column(Integer, nullable=True)

    # JSONB enables expression/GIN indexes and faster key extraction in Postgres.
    extra = Column(JSONB, nullable=False, default=dict)
