from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text
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

    # MITRE ATT&CK metadata
    mitre_tactic = Column(String(64), nullable=True, index=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique = Column(String(128), nullable=True)
    confidence = Column(Integer, nullable=False, default=50)

    description = Column(String(255), nullable=False)
    details = Column(JSONB, nullable=False, default=dict)

    # Rule provenance — captured at alert creation time
    detector_type = Column(String(32), nullable=True)
    rule_version = Column(Integer, nullable=True)
    rule_hash = Column(String(64), nullable=True)
    ruleset_version = Column(String(64), nullable=True)

    # SOC triage lifecycle
    status = Column(String(16), nullable=False, default="open", index=True)
    disposition = Column(String(32), nullable=True)
    priority = Column(Integer, nullable=True)
    assigned_to = Column(String(64), nullable=True)
    investigation_id = Column(Integer, nullable=True, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(64), nullable=True)
    closed_at = Column(DateTime, nullable=True)
    closed_by = Column(String(64), nullable=True)
    triage_notes = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)
    false_positive_reason = Column(String(64), nullable=True, index=False)

    @property
    def agent_id(self) -> str | None:
        details = self.details if isinstance(self.details, dict) else {}
        return str(details.get("agent_id") or "").strip() or None

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AlertRuleOverrideModel(Base):

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


from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AlertEvidenceModel(Base):
    __tablename__ = "alert_evidence"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, nullable=False, index=True)
    event_id = Column(Integer, nullable=True)

    # What kind of evidence this is and its role in the alert
    evidence_type = Column(String(32), nullable=False)
    evidence_role = Column(String(16), nullable=False, default="trigger")

    # The entity that matched
    entity_type = Column(String(64), nullable=True)
    entity_value = Column(String(255), nullable=True)

    # The specific field and value that triggered the rule
    matched_field = Column(String(128), nullable=True)
    matched_value = Column(String(255), nullable=True)

    summary = Column(String(512), nullable=True)
    raw_context = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
