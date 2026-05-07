"""alert evidence table and rule provenance columns

Revision ID: 20260506_0021
Revises: 20260506_0020
Create Date: 2026-05-06
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "20260506_0021"
down_revision = "20260506_0020"
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


def _has_table(table: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    provenance_cols = [
        ("detector_type", sa.String(32), None),
        ("rule_version", sa.Integer(), None),
        ("rule_hash", sa.String(64), None),
        ("ruleset_version", sa.String(64), None),
    ]
    for col_name, col_type, default in provenance_cols:
        if not _has_column("alerts", col_name):
            kwargs: dict = {"nullable": True}
            if default is not None:
                kwargs["server_default"] = default
            op.add_column("alerts", sa.Column(col_name, col_type, **kwargs))

    if not _has_table("alert_evidence"):
        op.create_table(
            "alert_evidence",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("alert_id", sa.Integer(), nullable=False),
            sa.Column("event_id", sa.Integer(), nullable=True),
            sa.Column("evidence_type", sa.String(32), nullable=False),
            sa.Column("evidence_role", sa.String(16), nullable=False, server_default="trigger"),
            sa.Column("entity_type", sa.String(64), nullable=True),
            sa.Column("entity_value", sa.String(255), nullable=True),
            sa.Column("matched_field", sa.String(128), nullable=True),
            sa.Column("matched_value", sa.String(255), nullable=True),
            sa.Column("summary", sa.String(512), nullable=True),
            sa.Column("raw_context", JSONB(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )

        conn = op.get_bind()
        res = conn.execute(
            sa.text(
                "SELECT 1 FROM pg_indexes WHERE tablename='alert_evidence' AND indexname='ix_alert_evidence_alert_id'"
            )
        )
        if not res.fetchone():
            op.create_index("ix_alert_evidence_alert_id", "alert_evidence", ["alert_id"])

        res = conn.execute(
            sa.text(
                "SELECT 1 FROM pg_indexes WHERE tablename='alert_evidence' AND indexname='ix_alert_evidence_id'"
            )
        )
        if not res.fetchone():
            op.create_index("ix_alert_evidence_id", "alert_evidence", ["id"])


def downgrade() -> None:
    op.drop_index("ix_alert_evidence_alert_id", table_name="alert_evidence")
    op.drop_index("ix_alert_evidence_id", table_name="alert_evidence")
    op.drop_table("alert_evidence")

    for col_name in ["ruleset_version", "rule_hash", "rule_version", "detector_type"]:
        if _has_column("alerts", col_name):
            op.drop_column("alerts", col_name)
