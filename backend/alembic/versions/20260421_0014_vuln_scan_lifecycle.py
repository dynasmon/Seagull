"""Refine vulnerability scan lifecycle and finding state semantics.

Revision ID: 20260421_0014
Revises: 20260419_0013
Create Date: 2026-04-21
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "20260421_0014"
down_revision = "20260419_0013"
branch_labels = None
depends_on = None


def _inspector():
    return inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in set(_inspector().get_table_names(schema="public"))


def _has_column(table_name: str, column_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return column_name in {col["name"] for col in _inspector().get_columns(table_name, schema="public")}


def _has_index(table_name: str, index_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return any(idx.get("name") == index_name for idx in _inspector().get_indexes(table_name, schema="public"))


def upgrade() -> None:
    if _has_table("vuln_scans"):
        if not _has_column("vuln_scans", "lifecycle_state"):
            op.add_column(
                "vuln_scans",
                sa.Column("lifecycle_state", sa.String(length=24), nullable=False, server_default=sa.text("'queued'")),
            )
        if not _has_column("vuln_scans", "current_phase"):
            op.add_column(
                "vuln_scans",
                sa.Column("current_phase", sa.String(length=32), nullable=False, server_default=sa.text("'queued'")),
            )
        if not _has_column("vuln_scans", "queued_at"):
            op.add_column("vuln_scans", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
        if not _has_column("vuln_scans", "acknowledged_at"):
            op.add_column("vuln_scans", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
        if not _has_column("vuln_scans", "last_progress_at"):
            op.add_column("vuln_scans", sa.Column("last_progress_at", sa.DateTime(timezone=True), nullable=True))
        if not _has_column("vuln_scans", "trigger_source"):
            op.add_column(
                "vuln_scans",
                sa.Column("trigger_source", sa.String(length=24), nullable=False, server_default=sa.text("'scheduled'")),
            )
        if not _has_column("vuln_scans", "error_summary"):
            op.add_column("vuln_scans", sa.Column("error_summary", sa.String(length=512), nullable=True))
        if not _has_column("vuln_scans", "phase_timestamps"):
            op.add_column(
                "vuln_scans",
                sa.Column(
                    "phase_timestamps",
                    postgresql.JSONB(astext_type=sa.Text()),
                    nullable=False,
                    server_default=sa.text("'{}'::jsonb"),
                ),
            )

        op.alter_column("vuln_scans", "started_at", existing_type=sa.DateTime(timezone=True), nullable=True)

        op.execute(
            """
            UPDATE vuln_scans
            SET queued_at = COALESCE(queued_at, started_at, created_at, now()),
                acknowledged_at = COALESCE(
                    acknowledged_at,
                    CASE
                        WHEN lower(COALESCE(status, '')) IN ('acknowledged', 'running', 'started', 'finished', 'done', 'completed', 'failed', 'error', 'cancelled')
                        THEN COALESCE(started_at, created_at, now())
                        ELSE NULL
                    END
                ),
                lifecycle_state = CASE
                    WHEN lower(COALESCE(status, '')) = 'queued' THEN 'queued'
                    WHEN lower(COALESCE(status, '')) = 'acknowledged' THEN 'acknowledged'
                    WHEN lower(COALESCE(status, '')) IN ('finished', 'done', 'completed') THEN 'completed'
                    WHEN lower(COALESCE(status, '')) IN ('failed', 'error') THEN 'failed'
                    WHEN lower(COALESCE(status, '')) = 'cancelled' THEN 'cancelled'
                    ELSE 'running'
                END,
                current_phase = CASE
                    WHEN lower(COALESCE(status, '')) = 'queued' THEN 'queued'
                    WHEN lower(COALESCE(status, '')) = 'acknowledged' THEN 'acknowledged'
                    WHEN lower(COALESCE(status, '')) IN ('finished', 'done', 'completed') THEN 'completed'
                    WHEN lower(COALESCE(status, '')) IN ('failed', 'error') THEN 'failed'
                    WHEN lower(COALESCE(status, '')) = 'cancelled' THEN 'cancelled'
                    ELSE 'running'
                END,
                last_progress_at = COALESCE(last_progress_at, finished_at, started_at, updated_at, created_at, now()),
                trigger_source = CASE
                    WHEN COALESCE(scope->>'manual_trigger', config->>'manual_trigger', 'false') IN ('true', 'True', '1') THEN 'manual'
                    WHEN COALESCE(trigger_source, '') <> '' THEN trigger_source
                    ELSE 'scheduled'
                END,
                phase_timestamps = COALESCE(phase_timestamps, '{}'::jsonb),
                status = CASE
                    WHEN lower(COALESCE(status, '')) = 'queued' THEN 'queued'
                    WHEN lower(COALESCE(status, '')) = 'acknowledged' THEN 'acknowledged'
                    WHEN lower(COALESCE(status, '')) IN ('finished', 'done', 'completed') THEN 'completed'
                    WHEN lower(COALESCE(status, '')) IN ('failed', 'error') THEN 'failed'
                    WHEN lower(COALESCE(status, '')) = 'cancelled' THEN 'cancelled'
                    ELSE 'running'
                END
            """
        )

        op.alter_column(
            "vuln_scans",
            "queued_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        )
        op.alter_column(
            "vuln_scans",
            "last_progress_at",
            existing_type=sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        )

        for old_index in [
            "idx_vuln_scans_started_at_id",
            "idx_vuln_scans_reporter_started",
            "idx_vuln_scans_status_started",
        ]:
            if _has_index("vuln_scans", old_index):
                op.drop_index(old_index, table_name="vuln_scans")

        if not _has_index("vuln_scans", "idx_vuln_scans_queued_at_id"):
            op.create_index("idx_vuln_scans_queued_at_id", "vuln_scans", ["queued_at", "id"], unique=False)
        if not _has_index("vuln_scans", "idx_vuln_scans_reporter_queued"):
            op.create_index("idx_vuln_scans_reporter_queued", "vuln_scans", ["reporter_agent_id", "queued_at", "id"], unique=False)
        if not _has_index("vuln_scans", "idx_vuln_scans_lifecycle_queued"):
            op.create_index("idx_vuln_scans_lifecycle_queued", "vuln_scans", ["lifecycle_state", "queued_at", "id"], unique=False)
        if not _has_index("vuln_scans", "idx_vuln_scans_phase_progress"):
            op.create_index("idx_vuln_scans_phase_progress", "vuln_scans", ["current_phase", "last_progress_at", "id"], unique=False)

    if _has_table("vuln_findings"):
        if not _has_column("vuln_findings", "observation_state"):
            op.add_column(
                "vuln_findings",
                sa.Column("observation_state", sa.String(length=32), nullable=False, server_default=sa.text("'observed'")),
            )
        if not _has_column("vuln_findings", "operator_disposition"):
            op.add_column(
                "vuln_findings",
                sa.Column("operator_disposition", sa.String(length=32), nullable=False, server_default=sa.text("'open'")),
            )

        op.execute(
            """
            UPDATE vuln_findings
            SET observation_state = CASE
                    WHEN lower(COALESCE(status, '')) IN ('resolved', 'closed') THEN 'resolved'
                    WHEN lower(COALESCE(status, '')) IN ('fixed', 'awaiting_verification') THEN 'awaiting_verification'
                    ELSE 'observed'
                END,
                operator_disposition = CASE
                    WHEN is_suppressed IS TRUE THEN 'suppressed'
                    WHEN lower(COALESCE(status, '')) IN ('accepted', 'accepted_risk') THEN 'accepted_risk'
                    ELSE 'open'
                END,
                status = CASE
                    WHEN lower(COALESCE(status, '')) IN ('resolved', 'closed') THEN 'resolved'
                    WHEN lower(COALESCE(status, '')) IN ('fixed', 'awaiting_verification') THEN 'fixed'
                    WHEN lower(COALESCE(status, '')) IN ('accepted', 'accepted_risk') THEN 'accepted'
                    WHEN is_suppressed IS TRUE THEN 'ignored'
                    ELSE 'open'
                END
            """
        )

        if not _has_index("vuln_findings", "idx_vuln_findings_observation_last_seen"):
            op.create_index(
                "idx_vuln_findings_observation_last_seen",
                "vuln_findings",
                ["observation_state", "last_seen_at", "id"],
                unique=False,
            )
        if not _has_index("vuln_findings", "idx_vuln_findings_disposition_last_seen"):
            op.create_index(
                "idx_vuln_findings_disposition_last_seen",
                "vuln_findings",
                ["operator_disposition", "last_seen_at", "id"],
                unique=False,
            )


def downgrade() -> None:
    if _has_table("vuln_findings"):
        if _has_index("vuln_findings", "idx_vuln_findings_disposition_last_seen"):
            op.drop_index("idx_vuln_findings_disposition_last_seen", table_name="vuln_findings")
        if _has_index("vuln_findings", "idx_vuln_findings_observation_last_seen"):
            op.drop_index("idx_vuln_findings_observation_last_seen", table_name="vuln_findings")
        if _has_column("vuln_findings", "operator_disposition"):
            op.drop_column("vuln_findings", "operator_disposition")
        if _has_column("vuln_findings", "observation_state"):
            op.drop_column("vuln_findings", "observation_state")

    if _has_table("vuln_scans"):
        op.execute(
            """
            UPDATE vuln_scans
            SET started_at = COALESCE(started_at, queued_at, created_at, now())
            WHERE started_at IS NULL
            """
        )

        if _has_index("vuln_scans", "idx_vuln_scans_phase_progress"):
            op.drop_index("idx_vuln_scans_phase_progress", table_name="vuln_scans")
        if _has_index("vuln_scans", "idx_vuln_scans_lifecycle_queued"):
            op.drop_index("idx_vuln_scans_lifecycle_queued", table_name="vuln_scans")
        if _has_index("vuln_scans", "idx_vuln_scans_reporter_queued"):
            op.drop_index("idx_vuln_scans_reporter_queued", table_name="vuln_scans")
        if _has_index("vuln_scans", "idx_vuln_scans_queued_at_id"):
            op.drop_index("idx_vuln_scans_queued_at_id", table_name="vuln_scans")

        if _has_column("vuln_scans", "phase_timestamps"):
            op.drop_column("vuln_scans", "phase_timestamps")
        if _has_column("vuln_scans", "error_summary"):
            op.drop_column("vuln_scans", "error_summary")
        if _has_column("vuln_scans", "trigger_source"):
            op.drop_column("vuln_scans", "trigger_source")
        if _has_column("vuln_scans", "last_progress_at"):
            op.drop_column("vuln_scans", "last_progress_at")
        if _has_column("vuln_scans", "acknowledged_at"):
            op.drop_column("vuln_scans", "acknowledged_at")
        if _has_column("vuln_scans", "queued_at"):
            op.drop_column("vuln_scans", "queued_at")
        if _has_column("vuln_scans", "current_phase"):
            op.drop_column("vuln_scans", "current_phase")
        if _has_column("vuln_scans", "lifecycle_state"):
            op.drop_column("vuln_scans", "lifecycle_state")

        op.alter_column("vuln_scans", "started_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        if not _has_index("vuln_scans", "idx_vuln_scans_started_at_id"):
            op.create_index("idx_vuln_scans_started_at_id", "vuln_scans", ["started_at", "id"], unique=False)
        if not _has_index("vuln_scans", "idx_vuln_scans_reporter_started"):
            op.create_index("idx_vuln_scans_reporter_started", "vuln_scans", ["reporter_agent_id", "started_at", "id"], unique=False)
        if not _has_index("vuln_scans", "idx_vuln_scans_status_started"):
            op.create_index("idx_vuln_scans_status_started", "vuln_scans", ["status", "started_at", "id"], unique=False)
