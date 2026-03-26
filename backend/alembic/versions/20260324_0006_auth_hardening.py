"""Auth hardening: token versioning on portal users.

Revision ID: 20260324_0006
Revises: 20260317_0005
Create Date: 2026-03-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260324_0006"
down_revision = "20260317_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("portal_users")}

    if "token_version" not in cols:
        op.add_column(
            "portal_users",
            sa.Column("token_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        )
    op.execute("UPDATE portal_users SET username = lower(trim(username)) WHERE username IS NOT NULL")
    op.alter_column("portal_users", "token_version", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("portal_users")}
    if "token_version" in cols:
        op.drop_column("portal_users", "token_version")
