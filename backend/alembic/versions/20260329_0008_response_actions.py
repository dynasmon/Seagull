"""Create response_actions table for SOAR-lite action requests.

Revision ID: 20260329_0008
Revises: 20260327_0007
Create Date: 2026-03-29
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260329_0008"
down_revision = "20260327_0007"
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

    if "response_actions" not in tables:
        op.create_table(
            "response_actions",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("action_type", sa.String(length=32), nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("requested_by", sa.String(length=64), nullable=False),
            sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        )

    tables_after = set(insp.get_table_names(schema="public"))
    if "response_actions" in tables_after and "ix_response_actions_agent_id" not in index_names:
        op.create_index("ix_response_actions_agent_id", "response_actions", ["agent_id"], unique=False)
    if "response_actions" in tables_after and "ix_response_actions_status" not in index_names:
        op.create_index("ix_response_actions_status", "response_actions", ["status"], unique=False)
    if "response_actions" in tables_after and "ix_response_actions_requested_at" not in index_names:
        op.create_index("ix_response_actions_requested_at", "response_actions", ["requested_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))

    if "response_actions" in tables:
        op.drop_table("response_actions")
