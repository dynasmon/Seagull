from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class UebaBaselineModel(Base):
    __tablename__ = "ueba_baselines"
    __table_args__ = (
        Index(
            "ix_ueba_baselines_detector_status_last_seen",
            "detector_id",
            "status",
            "last_observed_at",
        ),
        Index("ix_ueba_baselines_agent_last_seen", "agent_id", "last_observed_at"),
        Index(
            "ix_ueba_baselines_lookup",
            "detector_id",
            "agent_id",
            "entity_type",
            "entity_value",
            "metric_name",
            "bucket_key",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    baseline_key = Column(String(160), nullable=False, unique=True, index=True)
    detector_id = Column(String(96), nullable=False, index=True)
    detector_version = Column(Integer, nullable=False, default=1)

    agent_id = Column(String(64), nullable=True, index=True)
    entity_type = Column(String(64), nullable=False, index=True)
    entity_value = Column(String(256), nullable=False, index=True)
    metric_name = Column(String(96), nullable=False, index=True)
    bucket_key = Column(String(96), nullable=False, default="global")

    status = Column(String(16), nullable=False, default="warmup", index=True)
    sample_count = Column(Integer, nullable=False, default=0)
    warmup_started_at = Column(DateTime(timezone=True), nullable=False)
    matured_at = Column(DateTime(timezone=True), nullable=True)
    window_started_at = Column(DateTime(timezone=True), nullable=False)
    window_ended_at = Column(DateTime(timezone=True), nullable=False)
    last_observed_at = Column(DateTime(timezone=True), nullable=False, index=True)

    expected_value = Column(Float, nullable=True)
    dispersion = Column(Float, nullable=True)
    lower_bound = Column(Float, nullable=True)
    upper_bound = Column(Float, nullable=True)
    confidence = Column(Integer, nullable=False, default=0)

    state = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class UebaFindingModel(Base):
    __tablename__ = "ueba_findings"
    __table_args__ = (
        Index("ix_ueba_findings_last_seen_id", "last_seen_at", "id"),
        Index("ix_ueba_findings_status_last_seen", "status", "last_seen_at"),
        Index(
            "ix_ueba_findings_detector_status_last_seen",
            "detector_id",
            "status",
            "last_seen_at",
        ),
        Index("ix_ueba_findings_agent_last_seen", "agent_id", "last_seen_at"),
        Index("ix_ueba_findings_dedup_status", "dedup_key", "status"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_key = Column(String(160), nullable=False, unique=True, index=True)
    dedup_key = Column(String(256), nullable=False, index=True)

    detector_id = Column(String(96), nullable=False, index=True)
    detector_version = Column(Integer, nullable=False, default=1)
    baseline_id = Column(Integer, ForeignKey("ueba_baselines.id", ondelete="SET NULL"), nullable=True, index=True)

    agent_id = Column(String(64), nullable=True, index=True)
    entity_type = Column(String(64), nullable=False, index=True)
    entity_value = Column(String(256), nullable=False, index=True)
    metric_name = Column(String(96), nullable=False, index=True)
    bucket_key = Column(String(96), nullable=False, default="global")

    status = Column(String(16), nullable=False, default="open", index=True)
    severity = Column(String(16), nullable=False, default="medium", index=True)
    confidence = Column(Integer, nullable=False, default=50)
    risk_score = Column(Integer, nullable=False, default=0)

    expected_value = Column(Float, nullable=True)
    observed_value = Column(Float, nullable=True)
    deviation_score = Column(Float, nullable=True)

    first_seen_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=False, index=True)
    window_started_at = Column(DateTime(timezone=True), nullable=False)
    window_ended_at = Column(DateTime(timezone=True), nullable=False)
    cooldown_until = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    occurrence_count = Column(Integer, nullable=False, default=1)

    summary = Column(Text, nullable=False, default="")
    reason_codes = Column(JSONB, nullable=False, default=list)
    explanation = Column(JSONB, nullable=False, default=dict)

    alert_id = Column(Integer, nullable=True, index=True)
    mitre_tactic = Column(String(64), nullable=True, index=True)
    mitre_technique_id = Column(String(32), nullable=True, index=True)
    mitre_technique = Column(String(128), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class UebaFindingEvidenceModel(Base):
    __tablename__ = "ueba_finding_evidence"
    __table_args__ = (
        Index("ix_ueba_finding_evidence_finding_observed", "finding_id", "observed_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("ueba_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(Integer, nullable=True, index=True)
    alert_id = Column(Integer, nullable=True, index=True)

    evidence_type = Column(String(32), nullable=False)
    evidence_role = Column(String(16), nullable=False, default="trigger")
    observed_at = Column(DateTime(timezone=True), nullable=False)

    entity_type = Column(String(64), nullable=True)
    entity_value = Column(String(256), nullable=True)
    matched_field = Column(String(128), nullable=True)
    matched_value = Column(String(255), nullable=True)
    summary = Column(String(512), nullable=True)
    raw_context = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class UebaDetectorStateModel(Base):
    __tablename__ = "ueba_detector_states"

    detector_id = Column(String(96), primary_key=True)
    detector_version = Column(Integer, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    status = Column(String(16), nullable=False, default="idle", index=True)
    consecutive_failures = Column(Integer, nullable=False, default=0)

    baseline_count = Column(Integer, nullable=False, default=0)
    mature_baseline_count = Column(Integer, nullable=False, default=0)
    open_findings = Column(Integer, nullable=False, default=0)

    last_run_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_success_at = Column(DateTime(timezone=True), nullable=True)
    last_error_at = Column(DateTime(timezone=True), nullable=True)
    last_window_started_at = Column(DateTime(timezone=True), nullable=True)
    last_window_ended_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)

    error_type = Column(String(128), nullable=True)
    error_message = Column(String(512), nullable=True)
    context = Column(JSONB, nullable=False, default=dict)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class UebaDetectorRunModel(Base):
    __tablename__ = "ueba_detector_runs"
    __table_args__ = (
        Index("ix_ueba_detector_runs_detector_started", "detector_id", "started_at"),
        Index("ix_ueba_detector_runs_status_started", "status", "started_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    detector_id = Column(String(96), nullable=False, index=True)
    detector_version = Column(Integer, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=False, index=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(16), nullable=False, default="running", index=True)
    window_started_at = Column(DateTime(timezone=True), nullable=True)
    window_ended_at = Column(DateTime(timezone=True), nullable=True)

    scanned_events = Column(Integer, nullable=False, default=0)
    evaluated_entities = Column(Integer, nullable=False, default=0)
    baselines_created = Column(Integer, nullable=False, default=0)
    baselines_updated = Column(Integer, nullable=False, default=0)
    findings_created = Column(Integer, nullable=False, default=0)
    findings_updated = Column(Integer, nullable=False, default=0)
    alerts_created = Column(Integer, nullable=False, default=0)
    suppressions_applied = Column(Integer, nullable=False, default=0)
    duration_ms = Column(Integer, nullable=True)

    error_type = Column(String(128), nullable=True)
    error_message = Column(String(512), nullable=True)
    context = Column(JSONB, nullable=False, default=dict)
