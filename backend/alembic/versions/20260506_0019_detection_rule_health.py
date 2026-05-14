"""Add detection_rule_health table for per-rule runtime observability.

Revision ID: 20260506_0019
Revises: 20260503_0018
Create Date: 2026-05-06
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260506_0019"
down_revision = "20260503_0018"
branch_labels = None
depends_on = None


def _inspector():
    return inspect(op.get_bind())


def _has_table(name: str) -> bool:
    return name in set(_inspector().get_table_names(schema="public"))


def upgrade() -> None:
    if _has_table("detection_rule_health"):
        return

    op.create_table(
        "detection_rule_health",
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=True),
        sa.Column("content_hash", sa.String(length=16), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="healthy"),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("events_scanned", sa.Integer(), nullable=True),
        sa.Column("alerts_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suppressions_applied", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_type", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("rule_id"),
    )
    op.create_index("ix_detection_rule_health_status", "detection_rule_health", ["status"])
    op.create_index("ix_detection_rule_health_last_run_at", "detection_rule_health", ["last_run_at"])


def downgrade() -> None:
    if not _has_table("detection_rule_health"):
        return
    op.drop_index("ix_detection_rule_health_last_run_at", table_name="detection_rule_health")
    op.drop_index("ix_detection_rule_health_status", table_name="detection_rule_health")
    op.drop_table("detection_rule_health")
