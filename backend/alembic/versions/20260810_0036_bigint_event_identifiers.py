from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260810_0036"
down_revision = "20260803_0035"
branch_labels = None
depends_on = None

EVENT_IDENTIFIER_COLUMNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("net_events", ("id", "bytes")),
    ("attack_chain_steps", ("event_id",)),
    ("alert_evidence", ("event_id",)),
    ("correlation_incident_evidence", ("net_event_id",)),
    ("ueba_finding_evidence", ("event_id",)),
    ("search_index_offsets", ("last_id",)),
)

OWNED_SEQUENCES: tuple[tuple[str, str], ...] = (("net_events", "id"),)


def _column_types(table: str) -> dict[str, str]:
    rows = op.get_bind().execute(
        sa.text(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = :table"
        ),
        {"table": table},
    )
    return {str(name): str(data_type) for name, data_type in rows}


def _retype_columns(table: str, columns: tuple[str, ...], target: str) -> None:
    present = _column_types(table)
    if not present:
        return
    pending = [name for name in columns if present.get(name) not in (None, target)]
    if not pending:
        return
    clauses = ", ".join(f'ALTER COLUMN "{name}" TYPE {target}' for name in pending)
    op.execute(sa.text(f'ALTER TABLE "{table}" {clauses}'))


def _retype_owned_sequence(table: str, column: str, target: str) -> None:
    bind = op.get_bind()
    sequence = bind.execute(
        sa.text("SELECT pg_get_serial_sequence(:table, :column)"),
        {"table": table, "column": column},
    ).scalar()
    if not sequence:
        return
    op.execute(sa.text(f"ALTER SEQUENCE {sequence} AS {target}"))


def _apply(target: str) -> None:
    for table, columns in EVENT_IDENTIFIER_COLUMNS:
        _retype_columns(table, columns, target)
    for table, column in OWNED_SEQUENCES:
        _retype_owned_sequence(table, column, target)


def upgrade() -> None:
    _apply("bigint")


def downgrade() -> None:
    for table, column in OWNED_SEQUENCES:
        _retype_owned_sequence(table, column, "integer")
    for table, columns in reversed(EVENT_IDENTIFIER_COLUMNS):
        _retype_columns(table, columns, "integer")
