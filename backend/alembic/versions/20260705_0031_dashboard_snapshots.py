from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "20260705_0031"
down_revision = "20260703_0030"
branch_labels = None
depends_on = None


def _has_table(table: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    )
    return result.fetchone() is not None


def _has_index(table: str, index: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE tablename = :t AND indexname = :i"),
        {"t": table, "i": index},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    if not _has_table("dashboard_snapshots"):
        op.create_table(
            "dashboard_snapshots",
            sa.Column("page", sa.String(64), primary_key=True),
            sa.Column("scope_key", sa.String(512), primary_key=True),
            sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("payload", JSONB(), nullable=False, server_default="{}"),
            sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("computed_ms", sa.Float(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    for idx_name, cols in [
        ("ix_dashboard_snapshots_updated_at", ["updated_at"]),
        ("ix_dashboard_snapshots_page_computed_at", ["page", "computed_at"]),
    ]:
        if not _has_index("dashboard_snapshots", idx_name):
            op.create_index(idx_name, "dashboard_snapshots", cols)


def downgrade() -> None:
    for idx in [
        "ix_dashboard_snapshots_page_computed_at",
        "ix_dashboard_snapshots_updated_at",
    ]:
        if _has_index("dashboard_snapshots", idx):
            op.drop_index(idx, table_name="dashboard_snapshots")
    if _has_table("dashboard_snapshots"):
        op.drop_table("dashboard_snapshots")
