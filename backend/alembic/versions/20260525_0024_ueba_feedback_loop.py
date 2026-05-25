
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB  # noqa: F401  (kept for parity with sibling migrations)

from alembic import op

revision = "20260525_0024"
down_revision = "20260518_0023"
branch_labels = None
depends_on = None


def _has_table(table: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
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


def _has_column(table: str, column: str) -> bool:
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    )
    return result.fetchone() is not None


def _add_column(table: str, column: sa.Column) -> None:
    if not _has_column(table, column.name):
        op.add_column(table, column)


def upgrade() -> None:
    _add_column("ueba_baselines", sa.Column("feedback_fp_count", sa.Integer(), nullable=False, server_default="0"))
    _add_column("ueba_baselines", sa.Column("feedback_tp_count", sa.Integer(), nullable=False, server_default="0"))
    _add_column(
        "ueba_baselines",
        sa.Column("feedback_confidence_delta", sa.Integer(), nullable=False, server_default="0"),
    )
    _add_column(
        "ueba_baselines",
        sa.Column("feedback_sensitivity_scale", sa.Float(), nullable=False, server_default="1.0"),
    )
    _add_column(
        "ueba_baselines",
        sa.Column("feedback_cooldown_scale", sa.Float(), nullable=False, server_default="1.0"),
    )
    _add_column("ueba_baselines", sa.Column("feedback_last_verdict", sa.String(24), nullable=True))
    _add_column(
        "ueba_baselines",
        sa.Column("feedback_last_annotated_at", sa.DateTime(timezone=True), nullable=True),
    )

    _add_column("ueba_findings", sa.Column("latest_verdict", sa.String(24), nullable=True))
    _add_column("ueba_findings", sa.Column("latest_verdict_at", sa.DateTime(timezone=True), nullable=True))
    _add_column("ueba_findings", sa.Column("latest_verdict_by", sa.String(128), nullable=True))
    if not _has_index("ueba_findings", "ix_ueba_findings_latest_verdict"):
        op.create_index("ix_ueba_findings_latest_verdict", "ueba_findings", ["latest_verdict"], unique=False)

    if not _has_table("ueba_feedback"):
        op.create_table(
            "ueba_feedback",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "finding_id",
                sa.Integer(),
                sa.ForeignKey("ueba_findings.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("detector_id", sa.String(96), nullable=False),
            sa.Column("entity_type", sa.String(64), nullable=False),
            sa.Column("entity_value", sa.String(256), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("verdict", sa.String(24), nullable=False),
            sa.Column("annotated_by", sa.String(128), nullable=False),
            sa.Column("annotated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("suppression_ttl_seconds", sa.Integer(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("is_override", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )

    for idx_name, cols, unique in [
        ("ix_ueba_feedback_id", ["id"], False),
        ("ix_ueba_feedback_finding_id", ["finding_id"], False),
        ("ix_ueba_feedback_detector_id", ["detector_id"], False),
        ("ix_ueba_feedback_agent_id", ["agent_id"], False),
        ("ix_ueba_feedback_verdict", ["verdict"], False),
        ("ix_ueba_feedback_annotated_at", ["annotated_at"], False),
        ("ix_ueba_feedback_finding_annotated", ["finding_id", "annotated_at"], False),
        ("ix_ueba_feedback_scope", ["detector_id", "agent_id", "entity_type", "entity_value"], False),
        ("ix_ueba_feedback_verdict_annotated", ["verdict", "annotated_at"], False),
    ]:
        if not _has_index("ueba_feedback", idx_name):
            op.create_index(idx_name, "ueba_feedback", cols, unique=unique)

    if not _has_table("ueba_suppressions"):
        op.create_table(
            "ueba_suppressions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scope_key", sa.String(200), nullable=False),
            sa.Column("detector_id", sa.String(96), nullable=False),
            sa.Column("agent_id", sa.String(64), nullable=True),
            sa.Column("entity_type", sa.String(64), nullable=False),
            sa.Column("entity_value", sa.String(256), nullable=False),
            sa.Column("reason", sa.String(32), nullable=False, server_default="false_positive_feedback"),
            sa.Column(
                "feedback_id",
                sa.Integer(),
                sa.ForeignKey("ueba_feedback.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("annotated_by", sa.String(128), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        )

    for idx_name, cols, unique in [
        ("ix_ueba_suppressions_id", ["id"], False),
        ("ix_ueba_suppressions_scope_key", ["scope_key"], True),
        ("ix_ueba_suppressions_detector_id", ["detector_id"], False),
        ("ix_ueba_suppressions_agent_id", ["agent_id"], False),
        ("ix_ueba_suppressions_feedback_id", ["feedback_id"], False),
        ("ix_ueba_suppressions_expires_at", ["expires_at"], False),
        ("ix_ueba_suppressions_scope", ["detector_id", "agent_id", "entity_type", "entity_value"], False),
        ("ix_ueba_suppressions_active_expires", ["active", "expires_at"], False),
    ]:
        if not _has_index("ueba_suppressions", idx_name):
            op.create_index(idx_name, "ueba_suppressions", cols, unique=unique)

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


def downgrade() -> None:
    for idx in [
        "ix_ueba_peer_groups_computed",
        "ix_ueba_peer_groups_agent_computed",
        "ix_ueba_peer_groups_run_group",
        "ix_ueba_peer_groups_computed_at",
        "ix_ueba_peer_groups_group_id",
        "ix_ueba_peer_groups_agent_id",
        "ix_ueba_peer_groups_run_id",
        "ix_ueba_peer_groups_id",
    ]:
        if _has_index("ueba_peer_groups", idx):
            op.drop_index(idx, table_name="ueba_peer_groups")
    if _has_table("ueba_peer_groups"):
        op.drop_table("ueba_peer_groups")

    for idx in [
        "ix_ueba_ml_models_status_finished",
        "ix_ueba_ml_models_scope_status",
        "ix_ueba_ml_models_training_finished_at",
        "ix_ueba_ml_models_status",
        "ix_ueba_ml_models_detector_id",
        "ix_ueba_ml_models_agent_id",
        "ix_ueba_ml_models_model_type",
        "ix_ueba_ml_models_model_key",
        "ix_ueba_ml_models_id",
    ]:
        if _has_index("ueba_ml_models", idx):
            op.drop_index(idx, table_name="ueba_ml_models")
    if _has_table("ueba_ml_models"):
        op.drop_table("ueba_ml_models")

    for idx in [
        "ix_ueba_suppressions_active_expires",
        "ix_ueba_suppressions_scope",
        "ix_ueba_suppressions_expires_at",
        "ix_ueba_suppressions_feedback_id",
        "ix_ueba_suppressions_agent_id",
        "ix_ueba_suppressions_detector_id",
        "ix_ueba_suppressions_scope_key",
        "ix_ueba_suppressions_id",
    ]:
        if _has_index("ueba_suppressions", idx):
            op.drop_index(idx, table_name="ueba_suppressions")
    if _has_table("ueba_suppressions"):
        op.drop_table("ueba_suppressions")

    for idx in [
        "ix_ueba_feedback_verdict_annotated",
        "ix_ueba_feedback_scope",
        "ix_ueba_feedback_finding_annotated",
        "ix_ueba_feedback_annotated_at",
        "ix_ueba_feedback_verdict",
        "ix_ueba_feedback_agent_id",
        "ix_ueba_feedback_detector_id",
        "ix_ueba_feedback_finding_id",
        "ix_ueba_feedback_id",
    ]:
        if _has_index("ueba_feedback", idx):
            op.drop_index(idx, table_name="ueba_feedback")
    if _has_table("ueba_feedback"):
        op.drop_table("ueba_feedback")

    if _has_index("ueba_findings", "ix_ueba_findings_latest_verdict"):
        op.drop_index("ix_ueba_findings_latest_verdict", table_name="ueba_findings")
    for col in ("latest_verdict_by", "latest_verdict_at", "latest_verdict"):
        if _has_column("ueba_findings", col):
            op.drop_column("ueba_findings", col)

    for col in (
        "feedback_last_annotated_at",
        "feedback_last_verdict",
        "feedback_cooldown_scale",
        "feedback_sensitivity_scale",
        "feedback_confidence_delta",
        "feedback_tp_count",
        "feedback_fp_count",
    ):
        if _has_column("ueba_baselines", col):
            op.drop_column("ueba_baselines", col)
