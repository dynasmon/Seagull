"""Add hot columns for process execution, FIM, and heuristic-derived signals.

Revision ID: 20260404_0011
Revises: 20260401_0010
Create Date: 2026-04-04
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "20260404_0011"
down_revision = "20260401_0010"
branch_labels = None
depends_on = None


def _has_column(table_name: str, column_name: str) -> bool:
    cols = inspect(op.get_bind()).get_columns(table_name, schema="public")
    return any(str(c.get("name")) == column_name for c in cols)


def _has_index(table_name: str, index_name: str) -> bool:
    idx = inspect(op.get_bind()).get_indexes(table_name, schema="public")
    return any(str(i.get("name")) == index_name for i in idx)


def upgrade() -> None:
    cols = [
        ("proc_pid", sa.Integer()),
        ("proc_ppid", sa.Integer()),
        ("proc_name", sa.String(length=128)),
        ("proc_exe", sa.String(length=512)),
        ("proc_parent_name", sa.String(length=128)),
        ("fim_path", sa.String(length=1024)),
        ("fim_category", sa.String(length=64)),
        ("heuristic_name", sa.String(length=64)),
        ("heuristic_confidence", sa.SmallInteger()),
    ]
    for name, typ in cols:
        if not _has_column("net_events", name):
            op.add_column("net_events", sa.Column(name, typ, nullable=True))

    if not _has_index("net_events", "idx_net_events_proc_name_ts"):
        op.create_index(
            "idx_net_events_proc_name_ts",
            "net_events",
            ["proc_name", sa.text('"timestamp" DESC')],
            unique=False,
            postgresql_where=sa.text("event_type = 'proc_exec'"),
        )
    if not _has_index("net_events", "idx_net_events_fim_path_ts"):
        op.create_index(
            "idx_net_events_fim_path_ts",
            "net_events",
            ["fim_path", sa.text('"timestamp" DESC')],
            unique=False,
            postgresql_where=sa.text("event_type in ('fim_change','persistence_systemd','persistence_cron','ssh_key_change')"),
        )
    if not _has_index("net_events", "idx_net_events_heuristic_name_ts"):
        op.create_index(
            "idx_net_events_heuristic_name_ts",
            "net_events",
            ["heuristic_name", sa.text('"timestamp" DESC')],
            unique=False,
            postgresql_where=sa.text("event_type in ('beacon_suspect','exfil_suspect','c2_suspect','egress_anomaly')"),
        )

    op.execute(
        """
        UPDATE net_events
        SET
          proc_pid = CASE
            WHEN COALESCE(extra->>'pid', '') ~ '^-?[0-9]+$' THEN (extra->>'pid')::int
            ELSE NULL
          END,
          proc_ppid = CASE
            WHEN COALESCE(extra->>'ppid', '') ~ '^-?[0-9]+$' THEN (extra->>'ppid')::int
            ELSE NULL
          END,
          proc_name = COALESCE(NULLIF(extra->>'exe_name', ''), NULLIF(extra->>'comm', ''), NULLIF(extra->>'binary', '')),
          proc_exe = NULLIF(extra->>'exe_path', ''),
          proc_parent_name = COALESCE(NULLIF(extra->>'parent_exe_name', ''), NULLIF(extra->>'parent_comm', '')),
          fim_path = NULLIF(extra->>'path', ''),
          fim_category = NULLIF(extra->>'path_category', ''),
          heuristic_name = COALESCE(NULLIF(extra->>'heuristic_name', ''), NULLIF(extra->>'heuristic_kind', ''), NULLIF(extra->>'reason_kind', '')),
          heuristic_confidence = CASE
            WHEN COALESCE(extra->>'confidence', '') ~ '^-?[0-9]+$' THEN (extra->>'confidence')::smallint
            ELSE NULL
          END
        WHERE timestamp >= now() - interval '30 days'
        """
    )


def downgrade() -> None:
    if _has_index("net_events", "idx_net_events_heuristic_name_ts"):
        op.drop_index("idx_net_events_heuristic_name_ts", table_name="net_events")
    if _has_index("net_events", "idx_net_events_fim_path_ts"):
        op.drop_index("idx_net_events_fim_path_ts", table_name="net_events")
    if _has_index("net_events", "idx_net_events_proc_name_ts"):
        op.drop_index("idx_net_events_proc_name_ts", table_name="net_events")

    cols = [
        "heuristic_confidence",
        "heuristic_name",
        "fim_category",
        "fim_path",
        "proc_parent_name",
        "proc_exe",
        "proc_name",
        "proc_ppid",
        "proc_pid",
    ]
    for col in cols:
        if _has_column("net_events", col):
            op.drop_column("net_events", col)
