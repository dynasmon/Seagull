from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

revision = "20260616_0028"
down_revision = "20260612_0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    if "entity_baseline" not in set(insp.get_table_names()):
        op.create_table(
            "entity_baseline",
            sa.Column("entity_type", sa.String(length=64), nullable=False),
            sa.Column("entity_value", sa.String(length=255), nullable=False),
            sa.Column("feature", sa.String(length=64), nullable=False, server_default="presence"),
            sa.Column("first_seen_at", sa.DateTime(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(), nullable=False),
            sa.Column("count_7d", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("count_30d", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.PrimaryKeyConstraint("entity_type", "entity_value", "feature"),
        )

    insp = inspect(bind)
    existing = {ix["name"] for ix in insp.get_indexes("entity_baseline")}
    if "ix_entity_baseline_last_seen" not in existing:
        op.create_index("ix_entity_baseline_last_seen", "entity_baseline", ["last_seen_at"], unique=False)
    if "ix_entity_baseline_type_feature" not in existing:
        op.create_index(
            "ix_entity_baseline_type_feature",
            "entity_baseline",
            ["entity_type", "feature"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)
    if "entity_baseline" in set(insp.get_table_names()):
        indexes = {ix["name"] for ix in insp.get_indexes("entity_baseline")}
        if "ix_entity_baseline_type_feature" in indexes:
            op.drop_index("ix_entity_baseline_type_feature", table_name="entity_baseline")
        if "ix_entity_baseline_last_seen" in indexes:
            op.drop_index("ix_entity_baseline_last_seen", table_name="entity_baseline")
        op.drop_table("entity_baseline")
