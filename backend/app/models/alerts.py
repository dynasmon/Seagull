from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, JSON
from app.core.db import Base


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    rule_id = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="medium")

    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True, index=True)
    dst_port = Column(Integer, nullable=True)

    description = Column(String(255), nullable=False)
    details = Column(JSON, nullable=False, default={})
