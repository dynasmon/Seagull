from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AlertRuleOverrideModel(Base):
    """Per-rule overrides stored in DB.

    The baseline (authoritative) rule set lives in YAML under /rules.
    This table allows the portal to override a subset of fields without
    rebuilding or redeploying.
    """

    __tablename__ = "alert_rule_overrides"

    rule_id = Column(String(64), primary_key=True, index=True)

    enabled = Column(Boolean, nullable=True)
    severity = Column(String(16), nullable=True)
    # NOTE: "window" is a reserved keyword in PostgreSQL (WINDOW clause).
    # We force quoting so SQLAlchemy always emits it safely.
    window = Column("window", String(16), nullable=True, quote=True)
    cooldown = Column(String(16), nullable=True)
    min_events = Column(Integer, nullable=True)

    # Structured overrides
    condition = Column(JSONB, nullable=False, default=dict)
    schedule = Column(JSONB, nullable=False, default=dict)

    # Advanced override for any field (deep-merged into the base rule)
    patch = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
