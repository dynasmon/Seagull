"""Safely extend correlation rules for advanced strategy configuration.

Revision ID: 20260503_0018
Revises: 20260503_0017
Create Date: 2026-05-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260503_0018"
down_revision = "20260503_0017"
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


def upgrade() -> None:
    if not _has_table("correlation_rules"):
        op.create_table(
            "correlation_rules",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=96), nullable=False),
            sa.Column("description", sa.String(length=255), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="high"),
            sa.Column("strategy", sa.String(length=16), nullable=False, server_default="burst"),
            sa.Column("group_by", sa.String(length=32), nullable=False, server_default="src_ip"),
            sa.Column("window_seconds", sa.Integer(), nullable=False, server_default="600"),
            sa.Column("min_alerts", sa.Integer(), nullable=False, server_default="2"),
            sa.Column("include_patterns", JSONB(), nullable=False, server_default="[]"),
            sa.Column("exclude_patterns", JSONB(), nullable=False, server_default="[]"),
            sa.Column("stages", JSONB(), nullable=False, server_default="[]"),
            sa.Column("entity", JSONB(), nullable=True),
            sa.Column("strategy_config", JSONB(), nullable=True),
            sa.Column("risk_config", JSONB(), nullable=True),
            sa.Column("evidence_config", JSONB(), nullable=True),
            sa.Column("lifecycle_config", JSONB(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_correlation_rules_id", "correlation_rules", ["id"])
        return

    for column_name in ("entity", "strategy_config", "risk_config", "evidence_config", "lifecycle_config"):
        if not _has_column("correlation_rules", column_name):
            op.add_column("correlation_rules", sa.Column(column_name, JSONB(), nullable=True))


def downgrade() -> None:
    if not _has_table("correlation_rules"):
        return
    for column_name in ("lifecycle_config", "evidence_config", "risk_config", "strategy_config", "entity"):
        if _has_column("correlation_rules", column_name):
            op.drop_column("correlation_rules", column_name)
