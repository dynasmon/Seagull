from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260810_0037"
down_revision = "20260810_0036"
branch_labels = None
depends_on = None

REBUILT_GRAPH_TABLES: tuple[str, ...] = (
    "network_topology_nodes",
    "network_topology_edges",
    "network_topology_observations",
    "network_topology_snapshots",
    "exposure_asset_posture",
    "exposure_nodes",
    "exposure_edges",
    "exposure_findings",
    "exposure_score_history",
)


def _column_type(table: str, column: str) -> str | None:
    row = op.get_bind().execute(
        sa.text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = :table AND column_name = :column"
        ),
        {"table": table, "column": column},
    ).fetchone()
    return str(row[0]) if row else None


def _retype_identity(table: str, target: str) -> None:
    if _column_type(table, "id") in (None, target):
        return
    op.execute(sa.text(f'ALTER TABLE "{table}" ALTER COLUMN "id" TYPE {target}'))
    sequence = op.get_bind().execute(
        sa.text("SELECT pg_get_serial_sequence(:table, 'id')"),
        {"table": table},
    ).scalar()
    if sequence:
        op.execute(sa.text(f"ALTER SEQUENCE {sequence} AS {target}"))


def upgrade() -> None:
    for table in REBUILT_GRAPH_TABLES:
        _retype_identity(table, "bigint")


def downgrade() -> None:
    for table in reversed(REBUILT_GRAPH_TABLES):
        _retype_identity(table, "integer")
