
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260327_0007"
down_revision = "20260324_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))

    if "agent_credentials" not in tables:
        op.create_table(
            "agent_credentials",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("credential_salt", sa.String(length=64), nullable=False),
            sa.Column("credential_hash", sa.String(length=64), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column(
                "max_uses",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("1"),
            ),
            sa.Column(
                "used_uses",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.Column("rotated_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_reason", sa.String(length=256), nullable=True),
            sa.Column("issued_from_bootstrap_token_id", sa.Integer(), nullable=True),
            sa.Column("replaces_credential_id", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(
                ["agent_id"],
                ["agents.agent_id"],
                ondelete="CASCADE",
            ),
            sa.UniqueConstraint(
                "credential_hash",
                name="uq_agent_credentials_hash",
            ),
        )
        op.create_index(
            "ix_agent_credentials_agent_id",
            "agent_credentials",
            ["agent_id"],
            unique=False,
        )

    if "agent_identities" in tables:
        op.drop_table("agent_identities")


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))

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
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("last_seen_at", sa.DateTime(), nullable=True),
            sa.Column(
                "is_revoked",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_reason", sa.String(length=256), nullable=True),
            sa.Column(
                "metadata",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            ),
            sa.ForeignKeyConstraint(
                ["agent_id"],
                ["agents.agent_id"],
                ondelete="CASCADE",
            ),
            sa.UniqueConstraint(
                "fingerprint_sha256",
                name="uq_agent_identities_fingerprint",
            ),
        )
        op.create_index(
            "ix_agent_identities_agent_id",
            "agent_identities",
            ["agent_id"],
            unique=False,
        )

    if "agent_credentials" in tables:
        op.drop_table("agent_credentials")