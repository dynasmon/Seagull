from sqlalchemy import Column, Integer, String, DateTime, JSON
from app.core.db import Base


class NetEventModel(Base):
    __tablename__ = "net_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), index=True, nullable=False)
    event_type = Column(String(32), index=True, nullable=False)
    timestamp = Column(DateTime, index=True, nullable=False)

    src_ip = Column(String(45), index=True, nullable=True)
    dst_ip = Column(String(45), index=True, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    proto = Column(String(16), nullable=True)
    bytes = Column(Integer, nullable=True)

    extra = Column(JSON, nullable=False, default={})
