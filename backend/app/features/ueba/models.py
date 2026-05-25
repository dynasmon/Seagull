from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String, Text, func
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

    feedback_fp_count = Column(Integer, nullable=False, default=0, server_default="0")
    feedback_tp_count = Column(Integer, nullable=False, default=0, server_default="0")
    feedback_confidence_delta = Column(Integer, nullable=False, default=0, server_default="0")
    feedback_sensitivity_scale = Column(Float, nullable=False, default=1.0, server_default="1.0")
    feedback_cooldown_scale = Column(Float, nullable=False, default=1.0, server_default="1.0")
    feedback_last_verdict = Column(String(24), nullable=True)
    feedback_last_annotated_at = Column(DateTime(timezone=True), nullable=True)

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

    latest_verdict = Column(String(24), nullable=True, index=True)
    latest_verdict_at = Column(DateTime(timezone=True), nullable=True)
    latest_verdict_by = Column(String(128), nullable=True)

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


class UebaFeedbackModel(Base):
    __tablename__ = "ueba_feedback"
    __table_args__ = (
        Index("ix_ueba_feedback_finding_annotated", "finding_id", "annotated_at"),
        Index(
            "ix_ueba_feedback_scope",
            "detector_id",
            "agent_id",
            "entity_type",
            "entity_value",
        ),
        Index("ix_ueba_feedback_verdict_annotated", "verdict", "annotated_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("ueba_findings.id", ondelete="CASCADE"), nullable=False, index=True)

    detector_id = Column(String(96), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False)
    entity_value = Column(String(256), nullable=False)
    agent_id = Column(String(64), nullable=True, index=True)

    verdict = Column(String(24), nullable=False, index=True)
    annotated_by = Column(String(128), nullable=False)
    annotated_at = Column(DateTime(timezone=True), nullable=False, index=True)
    suppression_ttl_seconds = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)
    is_override = Column(Boolean, nullable=False, default=False, server_default="false")

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class UebaSuppressionModel(Base):
    __tablename__ = "ueba_suppressions"
    __table_args__ = (
        Index(
            "ix_ueba_suppressions_scope",
            "detector_id",
            "agent_id",
            "entity_type",
            "entity_value",
        ),
        Index("ix_ueba_suppressions_active_expires", "active", "expires_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scope_key = Column(String(200), nullable=False, unique=True, index=True)

    detector_id = Column(String(96), nullable=False, index=True)
    agent_id = Column(String(64), nullable=True, index=True)
    entity_type = Column(String(64), nullable=False)
    entity_value = Column(String(256), nullable=False)

    reason = Column(String(32), nullable=False, default="false_positive_feedback")
    feedback_id = Column(Integer, ForeignKey("ueba_feedback.id", ondelete="SET NULL"), nullable=True, index=True)
    annotated_by = Column(String(128), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    active = Column(Boolean, nullable=False, default=True, server_default="true")


class UebaMlModelModel(Base):
    __tablename__ = "ueba_ml_models"
    __table_args__ = (
        Index("ix_ueba_ml_models_scope_status", "detector_id", "agent_id", "model_type", "status"),
        Index("ix_ueba_ml_models_status_finished", "status", "training_finished_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    model_key = Column(String(220), nullable=False, index=True)
    model_type = Column(String(32), nullable=False, index=True)
    agent_id = Column(String(64), nullable=True, index=True)
    detector_id = Column(String(96), nullable=False, index=True)
    status = Column(String(24), nullable=False, default="active", server_default="active", index=True)

    serialized_model = Column(LargeBinary, nullable=False)
    feature_schema_version = Column(Integer, nullable=False)
    training_sample_count = Column(Integer, nullable=False, default=0)
    training_started_at = Column(DateTime(timezone=True), nullable=False)
    training_finished_at = Column(DateTime(timezone=True), nullable=False, index=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    anomaly_threshold = Column(Float, nullable=False, default=0.0)
    metadata_json = Column("metadata", JSONB, nullable=False, default=dict)


class UebaPeerGroupModel(Base):
    __tablename__ = "ueba_peer_groups"
    __table_args__ = (
        Index("ix_ueba_peer_groups_run_group", "run_id", "group_id"),
        Index("ix_ueba_peer_groups_agent_computed", "agent_id", "computed_at"),
        Index("ix_ueba_peer_groups_computed", "computed_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(36), nullable=False, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    group_id = Column(Integer, nullable=False, index=True)
    silhouette_score = Column(Float, nullable=True)
    fingerprint_vector = Column(JSONB, nullable=False, default=dict)
    computed_at = Column(DateTime(timezone=True), nullable=False, index=True)
    feature_schema_version = Column(Integer, nullable=False)

    centroid_vector = Column(JSONB, nullable=False, default=dict)
    covariance_matrix = Column(JSONB, nullable=False, default=dict)
    distance_threshold = Column(Float, nullable=True)
    group_size = Column(Integer, nullable=False, default=0)
    peer_agents = Column(JSONB, nullable=False, default=list)
    scoring_enabled = Column(Boolean, nullable=False, default=False, server_default="false")
