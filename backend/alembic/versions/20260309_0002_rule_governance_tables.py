"""Add dedicated rule governance tables (tuning/suppressions + history)."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260309_0002"
down_revision = "20260308_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = inspect(bind)

    tables = set(insp.get_table_names(schema="public"))
    index_names = {
        idx["name"]
        for table_name in tables
        for idx in insp.get_indexes(table_name, schema="public")
    }

    if "alert_rule_tuning" not in tables:
        op.create_table(
            "alert_rule_tuning",
            sa.Column("rule_id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("tuning", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.Column("updated_by_username", sa.String(length=64), nullable=True),
        )
    if "idx_alert_rule_tuning_updated_at" not in index_names and "alert_rule_tuning" in set(insp.get_table_names(schema="public")):
        op.create_index("idx_alert_rule_tuning_updated_at", "alert_rule_tuning", ["updated_at"], unique=False)

    if "alert_rule_tuning_history" not in tables:
        op.create_table(
            "alert_rule_tuning_history",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("rule_id", sa.String(length=64), nullable=False),
            sa.Column("action", sa.String(length=16), nullable=False),
            sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_username", sa.String(length=64), nullable=True),
        )
    if "idx_alert_rule_tuning_history_rule_created" not in index_names and "alert_rule_tuning_history" in set(insp.get_table_names(schema="public")):
        op.create_index("idx_alert_rule_tuning_history_rule_created", "alert_rule_tuning_history", ["rule_id", "created_at"], unique=False)

    if "alert_rule_suppressions" not in tables:
        op.create_table(
            "alert_rule_suppressions",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("rule_id", sa.String(length=64), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("reason", sa.String(length=255), nullable=True),
            sa.Column("when", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("until", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.Column("updated_by_username", sa.String(length=64), nullable=True),
        )
    if "idx_alert_rule_suppressions_rule_updated" not in index_names and "alert_rule_suppressions" in set(insp.get_table_names(schema="public")):
        op.create_index("idx_alert_rule_suppressions_rule_updated", "alert_rule_suppressions", ["rule_id", "updated_at"], unique=False)
    if "idx_alert_rule_suppressions_rule_enabled_until" not in index_names and "alert_rule_suppressions" in set(insp.get_table_names(schema="public")):
        op.create_index(
            "idx_alert_rule_suppressions_rule_enabled_until",
            "alert_rule_suppressions",
            ["rule_id", "enabled", "until"],
            unique=False,
        )

    if "alert_rule_suppressions_history" not in tables:
        op.create_table(
            "alert_rule_suppressions_history",
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("rule_id", sa.String(length=64), nullable=False),
            sa.Column("suppression_id", sa.Integer(), nullable=True),
            sa.Column("action", sa.String(length=16), nullable=False),
            sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_username", sa.String(length=64), nullable=True),
        )
    if "idx_alert_rule_supp_history_rule_created" not in index_names and "alert_rule_suppressions_history" in set(insp.get_table_names(schema="public")):
        op.create_index("idx_alert_rule_supp_history_rule_created", "alert_rule_suppressions_history", ["rule_id", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_alert_rule_supp_history_rule_created", table_name="alert_rule_suppressions_history")
    op.drop_table("alert_rule_suppressions_history")

    op.drop_index("idx_alert_rule_suppressions_rule_enabled_until", table_name="alert_rule_suppressions")
    op.drop_index("idx_alert_rule_suppressions_rule_updated", table_name="alert_rule_suppressions")
    op.drop_table("alert_rule_suppressions")

    op.drop_index("idx_alert_rule_tuning_history_rule_created", table_name="alert_rule_tuning_history")
    op.drop_table("alert_rule_tuning_history")

    op.drop_index("idx_alert_rule_tuning_updated_at", table_name="alert_rule_tuning")
    op.drop_table("alert_rule_tuning")
