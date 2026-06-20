
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260419_0013"
down_revision = "20260405_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    agent_cols = {c["name"] for c in insp.get_columns("agents", schema="public")}
    bootstrap_cols = {c["name"] for c in insp.get_columns("agent_bootstrap_tokens", schema="public")}
    index_names = {
        idx["name"]
        for table_name in ("agent_bootstrap_tokens", "agent_credentials")
        for idx in insp.get_indexes(table_name, schema="public")
    }

    # Classify bootstrap tokens by purpose (enrollment vs. automatic renewal).
    if "token_type" not in bootstrap_cols:
        op.add_column(
            "agent_bootstrap_tokens",
            sa.Column("token_type", sa.String(16), nullable=False, server_default="enrollment"),
        )
    op.execute("UPDATE agent_bootstrap_tokens SET token_type = 'enrollment' WHERE token_type IS NULL")
    if "ix_agent_bootstrap_tokens_agent_type" not in index_names:
        op.create_index(
            "ix_agent_bootstrap_tokens_agent_type",
            "agent_bootstrap_tokens",
            ["agent_id", "token_type"],
        )

    # Compound index for the active-credential lookup in the hot auth path.
    if "ix_agent_credentials_agent_revoked" not in index_names:
        op.create_index(
            "ix_agent_credentials_agent_revoked",
            "agent_credentials",
            ["agent_id", "revoked_at"],
        )
    # Supports expiry-window queries in the rotation scheduler.
    if "ix_agent_credentials_expires_at" not in index_names:
        op.create_index(
            "ix_agent_credentials_expires_at",
            "agent_credentials",
            ["expires_at"],
        )

    # Drop legacy columns that have been unused since the credential migration.
    if "key_salt" in agent_cols:
        op.drop_column("agents", "key_salt")
    if "key_hash" in agent_cols:
        op.drop_column("agents", "key_hash")


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    agent_cols = {c["name"] for c in insp.get_columns("agents", schema="public")}
    bootstrap_cols = {c["name"] for c in insp.get_columns("agent_bootstrap_tokens", schema="public")}
    index_names = {
        idx["name"]
        for table_name in ("agent_bootstrap_tokens", "agent_credentials")
        for idx in insp.get_indexes(table_name, schema="public")
    }
    if "key_hash" not in agent_cols:
        op.add_column("agents", sa.Column("key_hash", sa.String(64), nullable=False, server_default=""))
    if "key_salt" not in agent_cols:
        op.add_column("agents", sa.Column("key_salt", sa.String(64), nullable=False, server_default=""))
    if "ix_agent_credentials_expires_at" in index_names:
        op.drop_index("ix_agent_credentials_expires_at", table_name="agent_credentials")
    if "ix_agent_credentials_agent_revoked" in index_names:
        op.drop_index("ix_agent_credentials_agent_revoked", table_name="agent_credentials")
    if "ix_agent_bootstrap_tokens_agent_type" in index_names:
        op.drop_index("ix_agent_bootstrap_tokens_agent_type", table_name="agent_bootstrap_tokens")
    if "token_type" in bootstrap_cols:
        op.drop_column("agent_bootstrap_tokens", "token_type")
