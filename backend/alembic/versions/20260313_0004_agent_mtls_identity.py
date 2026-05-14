"""Add mTLS identity and bootstrap-token lifecycle tables for agents."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260313_0004"
down_revision = "20260311_0003"
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

    if "agent_identities" not in tables:
        op.create_table(
            "agent_identities",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("fingerprint_sha256", sa.String(length=128), nullable=False),
            sa.Column("serial_number", sa.String(length=128), nullable=False),
            sa.Column("subject_dn", sa.String(length=512), nullable=False),
            sa.Column("issuer_dn", sa.String(length=512), nullable=True),
            sa.Column("not_before", sa.DateTime(), nullable=True),
            sa.Column("not_after", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("last_seen_at", sa.DateTime(), nullable=True),
            sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_reason", sa.String(length=256), nullable=True),
            sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
            sa.UniqueConstraint("fingerprint_sha256", name="uq_agent_identities_fingerprint"),
        )

    tables = set(insp.get_table_names(schema="public"))
    if "ix_agent_identities_agent_id" not in index_names and "agent_identities" in tables:
        op.create_index("ix_agent_identities_agent_id", "agent_identities", ["agent_id"], unique=False)
    if "ix_agent_identities_fingerprint_sha256" not in index_names and "agent_identities" in tables:
        op.create_index("ix_agent_identities_fingerprint_sha256", "agent_identities", ["fingerprint_sha256"], unique=True)

    if "agent_bootstrap_tokens" not in tables:
        op.create_table(
            "agent_bootstrap_tokens",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("token_salt", sa.String(length=64), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("max_uses", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("used_uses", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_reason", sa.String(length=256), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("description", sa.String(length=256), nullable=True),
            sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.UniqueConstraint("token_hash", name="uq_agent_bootstrap_tokens_hash"),
        )

    tables = set(insp.get_table_names(schema="public"))
    if "ix_agent_bootstrap_tokens_agent_id" not in index_names and "agent_bootstrap_tokens" in tables:
        op.create_index("ix_agent_bootstrap_tokens_agent_id", "agent_bootstrap_tokens", ["agent_id"], unique=False)
    if "ix_agent_bootstrap_tokens_token_hash" not in index_names and "agent_bootstrap_tokens" in tables:
        op.create_index("ix_agent_bootstrap_tokens_token_hash", "agent_bootstrap_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_agent_bootstrap_tokens_token_hash", table_name="agent_bootstrap_tokens")
    op.drop_index("ix_agent_bootstrap_tokens_agent_id", table_name="agent_bootstrap_tokens")
    op.drop_table("agent_bootstrap_tokens")

    op.drop_index("ix_agent_identities_fingerprint_sha256", table_name="agent_identities")
    op.drop_index("ix_agent_identities_agent_id", table_name="agent_identities")
    op.drop_table("agent_identities")
