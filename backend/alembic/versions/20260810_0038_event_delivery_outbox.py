from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "20260810_0038"
down_revision = "20260810_0037"
branch_labels = None
depends_on = None


def _has_table(table: str) -> bool:
    row = op.get_bind().execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :table"),
        {"table": table},
    )
    return row.fetchone() is not None


def _has_index(table: str, index: str) -> bool:
    row = op.get_bind().execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE tablename = :table AND indexname = :index"),
        {"table": table, "index": index},
    )
    return row.fetchone() is not None


def upgrade() -> None:
    if not _has_table("event_outbox"):
        op.create_table(
            "event_outbox",
            sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column("sink", sa.String(32), nullable=False),
            sa.Column("payload", JSONB(), nullable=False),
            sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_error", sa.Text(), nullable=True),
        )

    if not _has_index("event_outbox", "ix_event_outbox_claim"):
        op.create_index("ix_event_outbox_claim", "event_outbox", ["sink", "available_at", "id"])

    if not _has_table("event_outbox_dead_letter"):
        op.create_table(
            "event_outbox_dead_letter",
            sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
            sa.Column("sink", sa.String(32), nullable=False),
            sa.Column("payload", JSONB(), nullable=False),
            sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reason", sa.String(64), nullable=False),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("failed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    if not _has_index("event_outbox_dead_letter", "ix_event_outbox_dead_letter_sink"):
        op.create_index(
            "ix_event_outbox_dead_letter_sink",
            "event_outbox_dead_letter",
            ["sink", "failed_at"],
        )


def downgrade() -> None:
    if _has_index("event_outbox_dead_letter", "ix_event_outbox_dead_letter_sink"):
        op.drop_index("ix_event_outbox_dead_letter_sink", table_name="event_outbox_dead_letter")
    if _has_table("event_outbox_dead_letter"):
        op.drop_table("event_outbox_dead_letter")
    if _has_index("event_outbox", "ix_event_outbox_claim"):
        op.drop_index("ix_event_outbox_claim", table_name="event_outbox")
    if _has_table("event_outbox"):
        op.drop_table("event_outbox")
