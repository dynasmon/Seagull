"""Inventory of issued agent client certificates.

Revision ID: 20260611_0026
Revises: 20260526_0025
Create Date: 2026-06-11
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260611_0026"
down_revision = "20260526_0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))

    if "agent_certificates" not in tables:
        op.create_table(
            "agent_certificates",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("agent_id", sa.String(length=64), nullable=False),
            sa.Column("serial_hex", sa.String(length=64), nullable=False),
            sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
            sa.Column("subject", sa.String(length=256), nullable=False),
            sa.Column("public_key_sha256", sa.String(length=64), nullable=False),
            sa.Column("issued_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column("revoked_reason", sa.String(length=256), nullable=True),
            sa.Column("status", sa.String(length=16), nullable=False, server_default=sa.text("'active'")),
            sa.ForeignKeyConstraint(
                ["agent_id"],
                ["agents.agent_id"],
                ondelete="CASCADE",
            ),
            sa.UniqueConstraint(
                "fingerprint_sha256",
                name="uq_agent_certificates_fingerprint",
            ),
        )
        op.create_index(
            "ix_agent_certificates_agent_id",
            "agent_certificates",
            ["agent_id"],
            unique=False,
        )
        op.create_index(
            "ix_agent_certificates_serial_hex",
            "agent_certificates",
            ["serial_hex"],
            unique=False,
        )
        op.create_index(
            "ix_agent_certificates_public_key_sha256",
            "agent_certificates",
            ["public_key_sha256"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))

    if "agent_certificates" in tables:
        op.drop_table("agent_certificates")
