from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.dialects.postgresql import JSONB

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

    # MITRE ATT&CK metadata (optional but first-class)
    mitre_tactic = Column(String(64), nullable=True, index=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique = Column(String(128), nullable=True)
    confidence = Column(Integer, nullable=False, default=50)

    description = Column(String(255), nullable=False)
    details = Column(JSONB, nullable=False, default=dict)

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

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AlertRuleTuningModel(Base):
    __tablename__ = "alert_rule_tuning"

    rule_id = Column(String(64), primary_key=True, index=True)
    tuning = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_by_user_id = Column(Integer, nullable=True)
    updated_by_username = Column(String(64), nullable=True)


class AlertRuleTuningHistoryModel(Base):
    __tablename__ = "alert_rule_tuning_history"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    action = Column(String(16), nullable=False)  # created | updated | deleted
    snapshot = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    actor_user_id = Column(Integer, nullable=True)
    actor_username = Column(String(64), nullable=True)
