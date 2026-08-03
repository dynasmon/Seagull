from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260803_0035"
down_revision = "20260803_0034"
branch_labels = None
depends_on = None


def _has_index(table: str, index: str) -> bool:
    result = op.get_bind().execute(
        sa.text(
            "SELECT 1 FROM pg_indexes "
            "WHERE schemaname = current_schema() AND tablename = :table AND indexname = :index"
        ),
        {"table": table, "index": index},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        if not _has_index("alerts", "idx_alerts_agent_created"):
            op.create_index(
                "idx_alerts_agent_created",
                "alerts",
                [sa.text("(details ->> 'agent_id')"), sa.text("created_at DESC"), sa.text("id DESC")],
                postgresql_concurrently=True,
            )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        if _has_index("alerts", "idx_alerts_agent_created"):
            op.drop_index("idx_alerts_agent_created", table_name="alerts", postgresql_concurrently=True)
