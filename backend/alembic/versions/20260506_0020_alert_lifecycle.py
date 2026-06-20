
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260506_0020"
down_revision = "20260506_0019"
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    cols = [
        ("status", sa.String(16), "open"),
        ("disposition", sa.String(32), None),
        ("priority", sa.Integer(), None),
        ("assigned_to", sa.String(64), None),
        ("investigation_id", sa.Integer(), None),
        ("acknowledged_at", sa.DateTime(), None),
        ("acknowledged_by", sa.String(64), None),
        ("closed_at", sa.DateTime(), None),
        ("closed_by", sa.String(64), None),
        ("triage_notes", sa.Text(), None),
        ("risk_score", sa.Integer(), None),
    ]

    for col_name, col_type, default in cols:
        if not _has_column("alerts", col_name):
            kwargs: dict = {"nullable": True}
            if default is not None:
                kwargs["server_default"] = default
            op.add_column("alerts", sa.Column(col_name, col_type, **kwargs))

    conn = op.get_bind()
    res = conn.execute(
        sa.text(
            "SELECT 1 FROM pg_indexes WHERE tablename='alerts' AND indexname='ix_alerts_status'"
        )
    )
    if not res.fetchone():
        op.create_index("ix_alerts_status", "alerts", ["status"])

    res = conn.execute(
        sa.text(
            "SELECT 1 FROM pg_indexes WHERE tablename='alerts' AND indexname='ix_alerts_investigation_id'"
        )
    )
    if not res.fetchone():
        op.create_index("ix_alerts_investigation_id", "alerts", ["investigation_id"])


def downgrade() -> None:
    op.drop_index("ix_alerts_investigation_id", table_name="alerts")
    op.drop_index("ix_alerts_status", table_name="alerts")

    for col_name in [
        "risk_score", "triage_notes", "closed_by", "closed_at",
        "acknowledged_by", "acknowledged_at", "investigation_id",
        "assigned_to", "priority", "disposition", "status",
    ]:
        if _has_column("alerts", col_name):
            op.drop_column("alerts", col_name)
