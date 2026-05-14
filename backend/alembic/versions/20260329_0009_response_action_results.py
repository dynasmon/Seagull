"""Create response_action_results table for action execution outcomes.

Revision ID: 20260329_0009
Revises: 20260329_0008
Create Date: 2026-03-29
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260329_0009"
down_revision = "20260329_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))
    index_names = {
        idx["name"]
        for table_name in tables
        for idx in insp.get_indexes(table_name, schema="public")
    }

    if "response_action_results" not in tables:
        op.create_table(
            "response_action_results",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("response_action_id", sa.Integer(), nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'queued'")),
            sa.Column("result_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.ForeignKeyConstraint(["response_action_id"], ["response_actions.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        )

    tables_after = set(insp.get_table_names(schema="public"))
    if "response_action_results" in tables_after and "ix_response_action_results_response_action_id" not in index_names:
        op.create_index("ix_response_action_results_response_action_id", "response_action_results", ["response_action_id"], unique=False)
    if "response_action_results" in tables_after and "ix_response_action_results_agent_id" not in index_names:
        op.create_index("ix_response_action_results_agent_id", "response_action_results", ["agent_id"], unique=False)
    if "response_action_results" in tables_after and "ix_response_action_results_status" not in index_names:
        op.create_index("ix_response_action_results_status", "response_action_results", ["status"], unique=False)
    if "response_action_results" in tables_after and "ix_response_action_results_finished_at" not in index_names:
        op.create_index("ix_response_action_results_finished_at", "response_action_results", ["finished_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))

    if "response_action_results" in tables:
        op.drop_table("response_action_results")
