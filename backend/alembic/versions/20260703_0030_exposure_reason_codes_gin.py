from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260703_0030"
down_revision = "20260616_0029"
branch_labels = None
depends_on = None


def _has_index(table: str, index: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE tablename = :t AND indexname = :i"),
        {"t": table, "i": index},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    if not _has_index("exposure_asset_posture", "gin_exposure_posture_reason_codes"):
        op.create_index(
            "gin_exposure_posture_reason_codes",
            "exposure_asset_posture",
            ["reason_codes"],
            unique=False,
            postgresql_using="gin",
        )
    if not _has_index("exposure_asset_posture", "gin_exposure_posture_top_recs"):
        op.create_index(
            "gin_exposure_posture_top_recs",
            "exposure_asset_posture",
            ["top_recommendations"],
            unique=False,
            postgresql_using="gin",
        )


def downgrade() -> None:
    if _has_index("exposure_asset_posture", "gin_exposure_posture_top_recs"):
        op.drop_index("gin_exposure_posture_top_recs", table_name="exposure_asset_posture")
    if _has_index("exposure_asset_posture", "gin_exposure_posture_reason_codes"):
        op.drop_index("gin_exposure_posture_reason_codes", table_name="exposure_asset_posture")
