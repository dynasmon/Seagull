from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260803_0034"
down_revision = "20260720_0033"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    result = op.get_bind().execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = :table AND column_name = :column"
        ),
        {"table": table, "column": column},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    if not _has_column("agents", "observed_address"):
        op.add_column("agents", sa.Column("observed_address", sa.String(45), nullable=True))
    if not _has_column("agents", "observed_address_at"):
        op.add_column("agents", sa.Column("observed_address_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    if _has_column("agents", "observed_address_at"):
        op.drop_column("agents", "observed_address_at")
    if _has_column("agents", "observed_address"):
        op.drop_column("agents", "observed_address")
