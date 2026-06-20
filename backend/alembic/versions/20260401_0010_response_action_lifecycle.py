
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260401_0010"
down_revision = "20260329_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))
    if "response_actions" not in tables:
        return

    cols = {c["name"] for c in insp.get_columns("response_actions", schema="public")}
    if "delivered_at" not in cols:
        op.add_column("response_actions", sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True))
    if "started_at" not in cols:
        op.add_column("response_actions", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
    if "finished_at" not in cols:
        op.add_column("response_actions", sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True))
    if "cancelled_at" not in cols:
        op.add_column("response_actions", sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True))
    if "cancelled_by" not in cols:
        op.add_column("response_actions", sa.Column("cancelled_by", sa.String(length=64), nullable=True))
    if "last_error" not in cols:
        op.add_column("response_actions", sa.Column("last_error", sa.Text(), nullable=True))

    index_names = {idx["name"] for idx in insp.get_indexes("response_actions", schema="public")}
    if "ix_response_actions_delivered_at" not in index_names:
        op.create_index("ix_response_actions_delivered_at", "response_actions", ["delivered_at"], unique=False)
    if "ix_response_actions_started_at" not in index_names:
        op.create_index("ix_response_actions_started_at", "response_actions", ["started_at"], unique=False)
    if "ix_response_actions_finished_at" not in index_names:
        op.create_index("ix_response_actions_finished_at", "response_actions", ["finished_at"], unique=False)
    if "ix_response_actions_cancelled_at" not in index_names:
        op.create_index("ix_response_actions_cancelled_at", "response_actions", ["cancelled_at"], unique=False)

    # Normalize stale legacy values from old flow where pending expiration became failed.
    op.execute(
        """
        UPDATE response_actions
        SET status = 'expired',
            last_error = COALESCE(last_error, 'action expired before execution'),
            finished_at = COALESCE(finished_at, now())
        WHERE status = 'failed'
          AND finished_at IS NULL
          AND started_at IS NULL
          AND delivered_at IS NULL
          AND expires_at IS NOT NULL
          AND expires_at <= now()
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    tables = set(insp.get_table_names(schema="public"))
    if "response_actions" not in tables:
        return

    index_names = {idx["name"] for idx in insp.get_indexes("response_actions", schema="public")}
    if "ix_response_actions_cancelled_at" in index_names:
        op.drop_index("ix_response_actions_cancelled_at", table_name="response_actions")
    if "ix_response_actions_finished_at" in index_names:
        op.drop_index("ix_response_actions_finished_at", table_name="response_actions")
    if "ix_response_actions_started_at" in index_names:
        op.drop_index("ix_response_actions_started_at", table_name="response_actions")
    if "ix_response_actions_delivered_at" in index_names:
        op.drop_index("ix_response_actions_delivered_at", table_name="response_actions")

    cols = {c["name"] for c in insp.get_columns("response_actions", schema="public")}
    if "last_error" in cols:
        op.drop_column("response_actions", "last_error")
    if "cancelled_by" in cols:
        op.drop_column("response_actions", "cancelled_by")
    if "cancelled_at" in cols:
        op.drop_column("response_actions", "cancelled_at")
    if "finished_at" in cols:
        op.drop_column("response_actions", "finished_at")
    if "started_at" in cols:
        op.drop_column("response_actions", "started_at")
    if "delivered_at" in cols:
        op.drop_column("response_actions", "delivered_at")
