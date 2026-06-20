
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260422_0015"
down_revision = "20260421_0014"
branch_labels = None
depends_on = None


def _inspector():
    return inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in set(_inspector().get_table_names(schema="public"))


def _has_column(table_name: str, column_name: str) -> bool:
    if not _has_table(table_name):
        return False
    return column_name in {col["name"] for col in _inspector().get_columns(table_name, schema="public")}


def upgrade() -> None:
    if not _has_table("vuln_scans"):
        return

    if not _has_column("vuln_scans", "request_token"):
        op.add_column("vuln_scans", sa.Column("request_token", sa.String(length=36), nullable=True))

    op.execute(
        """
        UPDATE vuln_scans
        SET request_token = COALESCE(
            NULLIF(scope->>'request_token', ''),
            NULLIF(scope->>'trigger_token', ''),
            CASE
                WHEN trigger_source = 'manual' THEN NULLIF(scan_uuid, '')
                ELSE NULL
            END
        )
        WHERE request_token IS NULL
        """
    )


def downgrade() -> None:
    if _has_column("vuln_scans", "request_token"):
        op.drop_column("vuln_scans", "request_token")
