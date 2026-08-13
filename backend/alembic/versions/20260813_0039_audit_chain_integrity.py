from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260813_0039"
down_revision = "20260810_0038"
branch_labels = None
depends_on = None


def _has_table(table: str) -> bool:
    row = op.get_bind().execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :table"),
        {"table": table},
    )
    return row.fetchone() is not None


def _has_column(table: str, column: str) -> bool:
    row = op.get_bind().execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :column"
        ),
        {"table": table, "column": column},
    )
    return row.fetchone() is not None


def _has_index(table: str, index: str) -> bool:
    row = op.get_bind().execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE tablename = :table AND indexname = :index"),
        {"table": table, "index": index},
    )
    return row.fetchone() is not None


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_column("admin_audit_events", "seq"):
        op.add_column("admin_audit_events", sa.Column("seq", sa.BigInteger(), nullable=True))
        bind.execute(
            sa.text(
                "UPDATE admin_audit_events AS a SET seq = ordered.rn "
                "FROM (SELECT id, row_number() OVER (ORDER BY created_at, id) AS rn "
                "FROM admin_audit_events) AS ordered "
                "WHERE a.id = ordered.id"
            )
        )

    if not _has_index("admin_audit_events", "ix_admin_audit_events_seq"):
        op.create_index("ix_admin_audit_events_seq", "admin_audit_events", ["seq"], unique=True)

    if not _has_table("audit_chain_head"):
        op.create_table(
            "audit_chain_head",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
            sa.Column("seq", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("head_hash", sa.String(64), nullable=True),
            sa.Column("chain_from_seq", sa.BigInteger(), nullable=False, server_default="1"),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )

    if not _has_table("audit_chain_checkpoints"):
        op.create_table(
            "audit_chain_checkpoints",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("from_seq", sa.BigInteger(), nullable=False),
            sa.Column("to_seq", sa.BigInteger(), nullable=False),
            sa.Column("pruned_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_event_hash", sa.String(64), nullable=True),
            sa.Column("prev_checkpoint_hash", sa.String(64), nullable=True),
            sa.Column("checkpoint_hash", sa.String(64), nullable=False),
        )

    if not _has_index("audit_chain_checkpoints", "ix_audit_chain_checkpoints_to_seq"):
        op.create_index("ix_audit_chain_checkpoints_to_seq", "audit_chain_checkpoints", ["to_seq"])
    if not _has_index("audit_chain_checkpoints", "ix_audit_chain_checkpoints_created_at"):
        op.create_index(
            "ix_audit_chain_checkpoints_created_at", "audit_chain_checkpoints", ["created_at"]
        )

    bind.execute(
        sa.text(
            "INSERT INTO audit_chain_head (id, seq, head_hash, chain_from_seq, updated_at) "
            "SELECT 1, COALESCE(MAX(seq), 0), NULL, COALESCE(MAX(seq), 0) + 1, now() "
            "FROM admin_audit_events "
            "ON CONFLICT (id) DO NOTHING"
        )
    )


def downgrade() -> None:
    if _has_index("audit_chain_checkpoints", "ix_audit_chain_checkpoints_created_at"):
        op.drop_index("ix_audit_chain_checkpoints_created_at", table_name="audit_chain_checkpoints")
    if _has_index("audit_chain_checkpoints", "ix_audit_chain_checkpoints_to_seq"):
        op.drop_index("ix_audit_chain_checkpoints_to_seq", table_name="audit_chain_checkpoints")
    if _has_table("audit_chain_checkpoints"):
        op.drop_table("audit_chain_checkpoints")
    if _has_table("audit_chain_head"):
        op.drop_table("audit_chain_head")
    if _has_index("admin_audit_events", "ix_admin_audit_events_seq"):
        op.drop_index("ix_admin_audit_events_seq", table_name="admin_audit_events")
    if _has_column("admin_audit_events", "seq"):
        op.drop_column("admin_audit_events", "seq")
