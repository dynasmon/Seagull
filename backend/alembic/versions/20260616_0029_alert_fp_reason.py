from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260616_0029"
down_revision = "20260616_0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    columns = {c["name"] for c in insp.get_columns("alerts")}
    if "false_positive_reason" not in columns:
        op.add_column("alerts", sa.Column("false_positive_reason", sa.String(length=64), nullable=True))

    insp = inspect(bind)
    indexes = {ix["name"] for ix in insp.get_indexes("alerts")}
    if "ix_alerts_fp_reason" not in indexes:
        op.create_index(
            "ix_alerts_fp_reason",
            "alerts",
            ["rule_id", "false_positive_reason"],
            unique=False,
            postgresql_where=sa.text("false_positive_reason IS NOT NULL"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    indexes = {ix["name"] for ix in insp.get_indexes("alerts")}
    if "ix_alerts_fp_reason" in indexes:
        op.drop_index("ix_alerts_fp_reason", table_name="alerts")
    columns = {c["name"] for c in insp.get_columns("alerts")}
    if "false_positive_reason" in columns:
        op.drop_column("alerts", "false_positive_reason")
