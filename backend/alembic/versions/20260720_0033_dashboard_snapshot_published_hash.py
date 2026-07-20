from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260720_0033"
down_revision = "20260707_0032"
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
    if not _has_column("dashboard_snapshots", "published_hash"):
        op.add_column("dashboard_snapshots", sa.Column("published_hash", sa.String(96), nullable=True))


def downgrade() -> None:
    if _has_column("dashboard_snapshots", "published_hash"):
        op.drop_column("dashboard_snapshots", "published_hash")
