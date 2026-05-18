"""UEBA durable foundation tables.

Revision ID: 20260518_0023
Revises: 20260511_0022
Create Date: 2026-05-18
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "20260518_0023"
down_revision = "20260511_0022"
branch_labels = None
depends_on = None


def _has_table(table: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    )
    return result.fetchone() is not None


def _has_index(table: str, index: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE tablename = :t AND indexname = :i"),
        {"t": table, "i": index},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    if not _has_table("ueba_baselines"):
        op.create_table(
            "ueba_baselines",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("baseline_key", sa.String(160), nullable=False),
            sa.Column("detector_id", sa.String(96), nullable=False),
            sa.Column("detector_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("entity_type", sa.String(64), nullable=False),
            sa.Column("entity_value", sa.String(256), nullable=False),
            sa.Column("metric_name", sa.String(96), nullable=False),
            sa.Column("bucket_key", sa.String(96), nullable=False, server_default="global"),
            sa.Column("status", sa.String(16), nullable=False, server_default="warmup"),
            sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("warmup_started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("matured_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("window_ended_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expected_value", sa.Float(), nullable=True),
            sa.Column("dispersion", sa.Float(), nullable=True),
            sa.Column("lower_bound", sa.Float(), nullable=True),
            sa.Column("upper_bound", sa.Float(), nullable=True),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("state", JSONB(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    for idx_name, cols, unique in [
        ("ix_ueba_baselines_id", ["id"], False),
        ("ix_ueba_baselines_baseline_key", ["baseline_key"], True),
        ("ix_ueba_baselines_detector_id", ["detector_id"], False),
        ("ix_ueba_baselines_agent_id", ["agent_id"], False),
        ("ix_ueba_baselines_entity_type", ["entity_type"], False),
        ("ix_ueba_baselines_entity_value", ["entity_value"], False),
        ("ix_ueba_baselines_metric_name", ["metric_name"], False),
        ("ix_ueba_baselines_status", ["status"], False),
        ("ix_ueba_baselines_last_observed_at", ["last_observed_at"], False),
        ("ix_ueba_baselines_detector_status_last_seen", ["detector_id", "status", "last_observed_at"], False),
        ("ix_ueba_baselines_agent_last_seen", ["agent_id", "last_observed_at"], False),
        (
            "ix_ueba_baselines_lookup",
            ["detector_id", "agent_id", "entity_type", "entity_value", "metric_name", "bucket_key"],
            False,
        ),
    ]:
        if not _has_index("ueba_baselines", idx_name):
            op.create_index(idx_name, "ueba_baselines", cols, unique=unique)

    if not _has_table("ueba_findings"):
        op.create_table(
            "ueba_findings",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("finding_key", sa.String(160), nullable=False),
            sa.Column("dedup_key", sa.String(256), nullable=False),
            sa.Column("detector_id", sa.String(96), nullable=False),
            sa.Column("detector_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("baseline_id", sa.Integer(), sa.ForeignKey("ueba_baselines.id", ondelete="SET NULL"), nullable=True),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("entity_type", sa.String(64), nullable=False),
            sa.Column("entity_value", sa.String(256), nullable=False),
            sa.Column("metric_name", sa.String(96), nullable=False),
            sa.Column("bucket_key", sa.String(96), nullable=False, server_default="global"),
            sa.Column("status", sa.String(16), nullable=False, server_default="open"),
            sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("expected_value", sa.Float(), nullable=True),
            sa.Column("observed_value", sa.Float(), nullable=True),
            sa.Column("deviation_score", sa.Float(), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("window_ended_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("cooldown_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("summary", sa.Text(), nullable=False, server_default=""),
            sa.Column("reason_codes", JSONB(), nullable=False, server_default="[]"),
            sa.Column("explanation", JSONB(), nullable=False, server_default="{}"),
            sa.Column("alert_id", sa.Integer(), nullable=True),
            sa.Column("mitre_tactic", sa.String(64), nullable=True),
            sa.Column("mitre_technique_id", sa.String(32), nullable=True),
            sa.Column("mitre_technique", sa.String(128), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    for idx_name, cols, unique in [
        ("ix_ueba_findings_id", ["id"], False),
        ("ix_ueba_findings_finding_key", ["finding_key"], True),
        ("ix_ueba_findings_dedup_key", ["dedup_key"], False),
        ("ix_ueba_findings_detector_id", ["detector_id"], False),
        ("ix_ueba_findings_baseline_id", ["baseline_id"], False),
        ("ix_ueba_findings_agent_id", ["agent_id"], False),
        ("ix_ueba_findings_entity_type", ["entity_type"], False),
        ("ix_ueba_findings_entity_value", ["entity_value"], False),
        ("ix_ueba_findings_metric_name", ["metric_name"], False),
        ("ix_ueba_findings_status", ["status"], False),
        ("ix_ueba_findings_severity", ["severity"], False),
        ("ix_ueba_findings_last_seen_at", ["last_seen_at"], False),
        ("ix_ueba_findings_alert_id", ["alert_id"], False),
        ("ix_ueba_findings_mitre_tactic", ["mitre_tactic"], False),
        ("ix_ueba_findings_mitre_technique_id", ["mitre_technique_id"], False),
        ("ix_ueba_findings_last_seen_id", ["last_seen_at", "id"], False),
        ("ix_ueba_findings_status_last_seen", ["status", "last_seen_at"], False),
        ("ix_ueba_findings_detector_status_last_seen", ["detector_id", "status", "last_seen_at"], False),
        ("ix_ueba_findings_agent_last_seen", ["agent_id", "last_seen_at"], False),
        ("ix_ueba_findings_dedup_status", ["dedup_key", "status"], False),
    ]:
        if not _has_index("ueba_findings", idx_name):
            op.create_index(idx_name, "ueba_findings", cols, unique=unique)

    if not _has_table("ueba_finding_evidence"):
        op.create_table(
            "ueba_finding_evidence",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("finding_id", sa.Integer(), sa.ForeignKey("ueba_findings.id", ondelete="CASCADE"), nullable=False),
            sa.Column("event_id", sa.Integer(), nullable=True),
            sa.Column("alert_id", sa.Integer(), nullable=True),
            sa.Column("evidence_type", sa.String(32), nullable=False),
            sa.Column("evidence_role", sa.String(16), nullable=False, server_default="trigger"),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("entity_type", sa.String(64), nullable=True),
            sa.Column("entity_value", sa.String(256), nullable=True),
            sa.Column("matched_field", sa.String(128), nullable=True),
            sa.Column("matched_value", sa.String(255), nullable=True),
            sa.Column("summary", sa.String(512), nullable=True),
            sa.Column("raw_context", JSONB(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    for idx_name, cols, unique in [
        ("ix_ueba_finding_evidence_id", ["id"], False),
        ("ix_ueba_finding_evidence_finding_id", ["finding_id"], False),
        ("ix_ueba_finding_evidence_event_id", ["event_id"], False),
        ("ix_ueba_finding_evidence_alert_id", ["alert_id"], False),
        ("ix_ueba_finding_evidence_finding_observed", ["finding_id", "observed_at"], False),
    ]:
        if not _has_index("ueba_finding_evidence", idx_name):
            op.create_index(idx_name, "ueba_finding_evidence", cols, unique=unique)

    if not _has_table("ueba_detector_states"):
        op.create_table(
            "ueba_detector_states",
            sa.Column("detector_id", sa.String(96), primary_key=True),
            sa.Column("detector_version", sa.Integer(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("status", sa.String(16), nullable=False, server_default="idle"),
            sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("baseline_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("mature_baseline_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("open_findings", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_window_started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_window_ended_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error_type", sa.String(128), nullable=True),
            sa.Column("error_message", sa.String(512), nullable=True),
            sa.Column("context", JSONB(), nullable=False, server_default="{}"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    for idx_name, cols, unique in [
        ("ix_ueba_detector_states_status", ["status"], False),
        ("ix_ueba_detector_states_last_run_at", ["last_run_at"], False),
    ]:
        if not _has_index("ueba_detector_states", idx_name):
            op.create_index(idx_name, "ueba_detector_states", cols, unique=unique)

    if not _has_table("ueba_detector_runs"):
        op.create_table(
            "ueba_detector_runs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("detector_id", sa.String(96), nullable=False),
            sa.Column("detector_version", sa.Integer(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(16), nullable=False, server_default="running"),
            sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("window_ended_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("scanned_events", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("evaluated_entities", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("baselines_created", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("baselines_updated", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("findings_created", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("findings_updated", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("alerts_created", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("suppressions_applied", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("error_type", sa.String(128), nullable=True),
            sa.Column("error_message", sa.String(512), nullable=True),
            sa.Column("context", JSONB(), nullable=False, server_default="{}"),
        )

    for idx_name, cols, unique in [
        ("ix_ueba_detector_runs_id", ["id"], False),
        ("ix_ueba_detector_runs_detector_id", ["detector_id"], False),
        ("ix_ueba_detector_runs_started_at", ["started_at"], False),
        ("ix_ueba_detector_runs_status", ["status"], False),
        ("ix_ueba_detector_runs_detector_started", ["detector_id", "started_at"], False),
        ("ix_ueba_detector_runs_status_started", ["status", "started_at"], False),
    ]:
        if not _has_index("ueba_detector_runs", idx_name):
            op.create_index(idx_name, "ueba_detector_runs", cols, unique=unique)


def downgrade() -> None:
    for table, indexes in [
        (
            "ueba_detector_runs",
            [
                "ix_ueba_detector_runs_status_started",
                "ix_ueba_detector_runs_detector_started",
                "ix_ueba_detector_runs_status",
                "ix_ueba_detector_runs_started_at",
                "ix_ueba_detector_runs_detector_id",
                "ix_ueba_detector_runs_id",
            ],
        ),
        (
            "ueba_detector_states",
            [
                "ix_ueba_detector_states_last_run_at",
                "ix_ueba_detector_states_status",
            ],
        ),
        (
            "ueba_finding_evidence",
            [
                "ix_ueba_finding_evidence_finding_observed",
                "ix_ueba_finding_evidence_alert_id",
                "ix_ueba_finding_evidence_event_id",
                "ix_ueba_finding_evidence_finding_id",
                "ix_ueba_finding_evidence_id",
            ],
        ),
        (
            "ueba_findings",
            [
                "ix_ueba_findings_dedup_status",
                "ix_ueba_findings_agent_last_seen",
                "ix_ueba_findings_detector_status_last_seen",
                "ix_ueba_findings_status_last_seen",
                "ix_ueba_findings_last_seen_id",
                "ix_ueba_findings_mitre_technique_id",
                "ix_ueba_findings_mitre_tactic",
                "ix_ueba_findings_alert_id",
                "ix_ueba_findings_last_seen_at",
                "ix_ueba_findings_severity",
                "ix_ueba_findings_status",
                "ix_ueba_findings_metric_name",
                "ix_ueba_findings_entity_value",
                "ix_ueba_findings_entity_type",
                "ix_ueba_findings_agent_id",
                "ix_ueba_findings_baseline_id",
                "ix_ueba_findings_detector_id",
                "ix_ueba_findings_dedup_key",
                "ix_ueba_findings_finding_key",
                "ix_ueba_findings_id",
            ],
        ),
        (
            "ueba_baselines",
            [
                "ix_ueba_baselines_lookup",
                "ix_ueba_baselines_agent_last_seen",
                "ix_ueba_baselines_detector_status_last_seen",
                "ix_ueba_baselines_last_observed_at",
                "ix_ueba_baselines_status",
                "ix_ueba_baselines_metric_name",
                "ix_ueba_baselines_entity_value",
                "ix_ueba_baselines_entity_type",
                "ix_ueba_baselines_agent_id",
                "ix_ueba_baselines_detector_id",
                "ix_ueba_baselines_baseline_key",
                "ix_ueba_baselines_id",
            ],
        ),
    ]:
        for idx in indexes:
            if _has_index(table, idx):
                op.drop_index(idx, table_name=table)
        if _has_table(table):
            op.drop_table(table)
