from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AlertRuleSuppressionModel(Base):
    __tablename__ = "alert_rule_suppressions"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    enabled = Column(Boolean, nullable=False, default=True)
    reason = Column(String(255), nullable=True)
    when = Column(JSONB, nullable=False, default=dict)
    until = Column(DateTime, nullable=True, index=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_by_user_id = Column(Integer, nullable=True)
    updated_by_username = Column(String(64), nullable=True)


class AlertRuleSuppressionHistoryModel(Base):
    __tablename__ = "alert_rule_suppressions_history"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    suppression_id = Column(Integer, nullable=True, index=True)
    action = Column(String(16), nullable=False)  # created | updated | deleted
    snapshot = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    actor_user_id = Column(Integer, nullable=True)
    actor_username = Column(String(64), nullable=True)
