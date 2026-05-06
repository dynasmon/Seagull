from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from app.core.db import Base


class DetectionRuleHealthModel(Base):
    __tablename__ = "detection_rule_health"

    rule_id = Column(String(64), primary_key=True)
    rule_version = Column(Integer, nullable=True)
    content_hash = Column(String(16), nullable=True)

    status = Column(String(16), nullable=False, default="healthy")
    consecutive_failures = Column(Integer, nullable=False, default=0)

    last_run_at = Column(DateTime, nullable=True)
    last_success_at = Column(DateTime, nullable=True)
    last_error_at = Column(DateTime, nullable=True)

    duration_ms = Column(Integer, nullable=True)
    events_scanned = Column(Integer, nullable=True)
    alerts_created = Column(Integer, nullable=False, default=0)
    suppressions_applied = Column(Integer, nullable=False, default=0)

    error_type = Column(String(128), nullable=True)
    error_message = Column(String(512), nullable=True)

    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
