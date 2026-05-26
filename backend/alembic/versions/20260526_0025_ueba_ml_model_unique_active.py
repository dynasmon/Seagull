
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "20260526_0025"
down_revision = "20260525_0024"
branch_labels = None
depends_on = None

_IDX = "uix_ueba_ml_models_one_active_per_scope"
_TABLE = "ueba_ml_models"


def _has_table(table: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename = :t"),
        {"t": table},
    )
    return result.fetchone() is not None


def _has_index(table: str, index: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM pg_indexes WHERE tablename = :t AND indexname = :i"),
        {"t": table, "i": index},
    )
    return result.fetchone() is not None


def upgrade() -> None:
    if not _has_table("ueba_ml_models"):
        op.create_table(
            "ueba_ml_models",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("model_key", sa.String(220), nullable=False),
            sa.Column("model_type", sa.String(32), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("detector_id", sa.String(96), nullable=False),
            sa.Column("status", sa.String(24), nullable=False, server_default="active"),
            sa.Column("serialized_model", sa.LargeBinary(), nullable=False),
            sa.Column("feature_schema_version", sa.Integer(), nullable=False),
            sa.Column("training_sample_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("training_started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("training_finished_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("anomaly_threshold", sa.Float(), nullable=False, server_default="0.0"),
            sa.Column("metadata", JSONB(), nullable=False, server_default="{}"),
        )
    for idx_name, cols, unique in [
        ("ix_ueba_ml_models_id", ["id"], False),
        ("ix_ueba_ml_models_model_key", ["model_key"], False),
        ("ix_ueba_ml_models_model_type", ["model_type"], False),
        ("ix_ueba_ml_models_agent_id", ["agent_id"], False),
        ("ix_ueba_ml_models_detector_id", ["detector_id"], False),
        ("ix_ueba_ml_models_status", ["status"], False),
        ("ix_ueba_ml_models_training_finished_at", ["training_finished_at"], False),
        ("ix_ueba_ml_models_scope_status", ["detector_id", "agent_id", "model_type", "status"], False),
        ("ix_ueba_ml_models_status_finished", ["status", "training_finished_at"], False),
    ]:
        if not _has_index("ueba_ml_models", idx_name):
            op.create_index(idx_name, "ueba_ml_models", cols, unique=unique)

    if not _has_table("ueba_peer_groups"):
        op.create_table(
            "ueba_peer_groups",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("run_id", sa.String(36), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=False),
            sa.Column("group_id", sa.Integer(), nullable=False),
            sa.Column("silhouette_score", sa.Float(), nullable=True),
            sa.Column("fingerprint_vector", JSONB(), nullable=False, server_default="{}"),
            sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("feature_schema_version", sa.Integer(), nullable=False),
            sa.Column("centroid_vector", JSONB(), nullable=False, server_default="{}"),
            sa.Column("covariance_matrix", JSONB(), nullable=False, server_default="{}"),
            sa.Column("distance_threshold", sa.Float(), nullable=True),
            sa.Column("group_size", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("peer_agents", JSONB(), nullable=False, server_default="[]"),
            sa.Column("scoring_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    for idx_name, cols, unique in [
        ("ix_ueba_peer_groups_id", ["id"], False),
        ("ix_ueba_peer_groups_run_id", ["run_id"], False),
        ("ix_ueba_peer_groups_agent_id", ["agent_id"], False),
        ("ix_ueba_peer_groups_group_id", ["group_id"], False),
        ("ix_ueba_peer_groups_computed_at", ["computed_at"], False),
        ("ix_ueba_peer_groups_run_group", ["run_id", "group_id"], False),
        ("ix_ueba_peer_groups_agent_computed", ["agent_id", "computed_at"], False),
        ("ix_ueba_peer_groups_computed", ["computed_at"], False),
    ]:
        if not _has_index("ueba_peer_groups", idx_name):
            op.create_index(idx_name, "ueba_peer_groups", cols, unique=unique)

    if not _has_index(_TABLE, _IDX):
        op.execute(
            sa.text(
                f"CREATE UNIQUE INDEX {_IDX} "
                f"ON {_TABLE} (detector_id, agent_id, model_type) "
                f"WHERE status = 'active'"
            )
        )


def downgrade() -> None:
    if _has_index(_TABLE, _IDX):
        op.execute(sa.text(f"DROP INDEX IF EXISTS {_IDX}"))
