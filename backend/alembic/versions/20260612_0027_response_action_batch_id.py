from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260612_0027"
down_revision = "20260611_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    columns = {c["name"] for c in insp.get_columns("response_actions")}
    indexes = {ix["name"] for ix in insp.get_indexes("response_actions")}

    if "batch_id" not in columns:
        op.add_column("response_actions", sa.Column("batch_id", sa.String(length=64), nullable=True))
    if "ix_response_actions_batch_id" not in indexes:
        op.create_index(
            "ix_response_actions_batch_id",
            "response_actions",
            ["batch_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    columns = {c["name"] for c in insp.get_columns("response_actions")}
    indexes = {ix["name"] for ix in insp.get_indexes("response_actions")}

    if "ix_response_actions_batch_id" in indexes:
        op.drop_index("ix_response_actions_batch_id", table_name="response_actions")
    if "batch_id" in columns:
        op.drop_column("response_actions", "batch_id")
