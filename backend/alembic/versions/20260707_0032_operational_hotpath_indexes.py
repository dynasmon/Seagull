from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260707_0032"
down_revision = "20260705_0031"
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
        if not _has_index("alerts", "idx_alerts_rule_sev_created_open"):
            # Serves the open alerts queue filtered by rule and severity with cursor ordering.
            op.create_index(
                "idx_alerts_rule_sev_created_open",
                "alerts",
                ["rule_id", "severity", sa.text("created_at DESC"), sa.text("id DESC")],
                postgresql_where=sa.text("status = 'open'"),
                postgresql_concurrently=True,
            )

        if not _has_index("exposure_findings", "idx_exposure_findings_asset_type_seen_open"):
            # Serves open exposure findings filtered by asset and finding type with cursor ordering.
            op.create_index(
                "idx_exposure_findings_asset_type_seen_open",
                "exposure_findings",
                ["asset_key", "finding_type", sa.text("last_seen_at DESC"), sa.text("id DESC")],
                postgresql_where=sa.text("status = 'open'"),
                postgresql_concurrently=True,
            )

        if not _has_index("vuln_findings", "idx_vuln_findings_agent_status_seen_unsuppressed"):
            # Serves unsuppressed vulnerability findings filtered by asset agent and status with cursor ordering.
            op.create_index(
                "idx_vuln_findings_agent_status_seen_unsuppressed",
                "vuln_findings",
                ["asset_agent_id", "status", sa.text("last_seen_at DESC"), sa.text("id DESC")],
                postgresql_where=sa.text("operator_disposition <> 'suppressed'"),
                postgresql_concurrently=True,
            )

        if not _has_index("correlation_incidents", "idx_correlation_incidents_last_seen"):
            # Serves the unfiltered incident feed in last-seen cursor order.
            op.create_index(
                "idx_correlation_incidents_last_seen",
                "correlation_incidents",
                [sa.text("last_seen_at DESC"), sa.text("id DESC")],
                postgresql_concurrently=True,
            )

        if not _has_index("correlation_incidents", "idx_correlation_incidents_status_last_seen"):
            # Serves the incident feed filtered by status in last-seen cursor order.
            op.create_index(
                "idx_correlation_incidents_status_last_seen",
                "correlation_incidents",
                ["status", sa.text("last_seen_at DESC"), sa.text("id DESC")],
                postgresql_concurrently=True,
            )

        if not _has_index("correlation_incidents", "idx_correlation_incidents_rule_group_started_open"):
            # Serves worker lookup of the newest open incident for a correlation rule and group.
            op.create_index(
                "idx_correlation_incidents_rule_group_started_open",
                "correlation_incidents",
                ["correlation_rule_id", "group_value", sa.text("started_at DESC")],
                postgresql_where=sa.text("status IN ('open', 'triaged')"),
                postgresql_concurrently=True,
            )

        if not _has_index("response_actions", "idx_response_actions_agent_requested"):
            # Serves response action history filtered by agent in requested-at cursor order.
            op.create_index(
                "idx_response_actions_agent_requested",
                "response_actions",
                ["agent_id", sa.text("requested_at DESC"), sa.text("id DESC")],
                postgresql_concurrently=True,
            )

        if not _has_index("response_actions", "idx_response_actions_status_requested"):
            # Serves response action history filtered by status in requested-at cursor order.
            op.create_index(
                "idx_response_actions_status_requested",
                "response_actions",
                ["status", sa.text("requested_at DESC"), sa.text("id DESC")],
                postgresql_concurrently=True,
            )


def downgrade() -> None:
    indexes = [
        ("response_actions", "idx_response_actions_status_requested"),
        ("response_actions", "idx_response_actions_agent_requested"),
        ("correlation_incidents", "idx_correlation_incidents_rule_group_started_open"),
        ("correlation_incidents", "idx_correlation_incidents_status_last_seen"),
        ("correlation_incidents", "idx_correlation_incidents_last_seen"),
        ("vuln_findings", "idx_vuln_findings_agent_status_seen_unsuppressed"),
        ("exposure_findings", "idx_exposure_findings_asset_type_seen_open"),
        ("alerts", "idx_alerts_rule_sev_created_open"),
    ]
    with op.get_context().autocommit_block():
        for table, index in indexes:
            if _has_index(table, index):
                op.drop_index(index, table_name=table, postgresql_concurrently=True)
