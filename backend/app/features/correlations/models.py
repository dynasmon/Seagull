from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class CorrelationRuleModel(Base):

    __tablename__ = "correlation_rules"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(96), nullable=False)
    description = Column(String(255), nullable=True)

    enabled = Column(Boolean, nullable=False, default=True)
    severity = Column(String(16), nullable=False, default="high")

    # Correlation configuration
    strategy = Column(String(16), nullable=False, default="burst")  # burst | chain
    group_by = Column(String(32), nullable=False, default="src_ip")
    window_seconds = Column(Integer, nullable=False, default=600)
    min_alerts = Column(Integer, nullable=False, default=2)

    include_patterns = Column(JSONB, nullable=False, default=list)
    exclude_patterns = Column(JSONB, nullable=False, default=list)
    stages = Column(JSONB, nullable=False, default=list)
    entity = Column(JSONB, nullable=True)
    strategy_config = Column(JSONB, nullable=True)
    risk_config = Column(JSONB, nullable=True)
    evidence_config = Column(JSONB, nullable=True)
    lifecycle_config = Column(JSONB, nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class CorrelationIncidentModel(Base):
    __tablename__ = "correlation_incidents"

    id = Column(Integer, primary_key=True, index=True)
    correlation_rule_id = Column(Integer, nullable=True)
    correlation_rule_name = Column(String(96), nullable=False)
    status = Column(String(16), nullable=False, default="open")  # open|triaged|closed|suppressed
    severity = Column(String(16), nullable=False, default="high")
    risk_score = Column(Integer, nullable=True)
    confidence = Column(Integer, nullable=True)
    entity_type = Column(String(32), nullable=True)
    entity_value = Column(String(256), nullable=True)
    group_by = Column(String(32), nullable=False, default="src_ip")
    group_value = Column(String(256), nullable=False, default="")
    dedup_key = Column(String(512), nullable=False, index=True)
    started_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False)
    closed_at = Column(DateTime, nullable=True)
    alert_count = Column(Integer, nullable=False, default=0)
    unique_rules = Column(JSONB, nullable=False, default=list)
    stage_hits = Column(JSONB, nullable=False, default=dict)
    summary = Column(Text, nullable=True)
    context = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class CorrelationIncidentEvidenceModel(Base):
    __tablename__ = "correlation_incident_evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("correlation_incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(Integer, nullable=True, index=True)
    net_event_id = Column(Integer, nullable=True, index=True)
    evidence_type = Column(String(32), nullable=False, default="alert")
    rule_id = Column(String(128), nullable=True)
    stage = Column(String(64), nullable=True)
    timestamp = Column(DateTime, nullable=False)
    src_ip = Column(String(64), nullable=True)
    dst_ip = Column(String(64), nullable=True)
    dst_port = Column(Integer, nullable=True)
    details = Column(JSONB, nullable=False, default=dict)


class CorrelationRuleRunModel(Base):
    __tablename__ = "correlation_rule_runs"

    id = Column(Integer, primary_key=True, index=True)
    correlation_rule_id = Column(Integer, nullable=True)
    started_at = Column(DateTime, nullable=False, index=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(16), nullable=False, default="running")  # running|completed|failed
    scanned_alerts = Column(Integer, nullable=False, default=0)
    incidents_created = Column(Integer, nullable=False, default=0)
    incidents_updated = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)
    context = Column(JSONB, nullable=False, default=dict)


class CorrelationEntityStateModel(Base):
    __tablename__ = "correlation_entity_states"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(32), nullable=False)
    entity_value = Column(String(256), nullable=False)
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False)
    seen_count = Column(Integer, nullable=False, default=1)
    last_context = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class EntityBaselineModel(Base):
    __tablename__ = "entity_baseline"
    __table_args__ = (
        Index("ix_entity_baseline_last_seen", "last_seen_at"),
        Index("ix_entity_baseline_type_feature", "entity_type", "feature"),
    )

    entity_type = Column(String(64), primary_key=True, nullable=False)
    entity_value = Column(String(255), primary_key=True, nullable=False)
    feature = Column(String(64), primary_key=True, nullable=False, default="presence", server_default="presence")
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False)
    count_7d = Column(Integer, nullable=False, default=0, server_default="0")
    count_30d = Column(Integer, nullable=False, default=0, server_default="0")
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
