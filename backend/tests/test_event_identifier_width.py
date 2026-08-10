import importlib.util
import os
from pathlib import Path

os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import pytest
from sqlalchemy import BigInteger

from app.core.db import Base
from app.core.db.model_registry import load_all_models

INT4_MAX = 2147483647

EVENT_IDENTIFIER_COLUMNS = {
    ("net_events", "id"),
    ("net_events", "bytes"),
    ("attack_chain_steps", "event_id"),
    ("alert_evidence", "event_id"),
    ("correlation_incident_evidence", "net_event_id"),
    ("ueba_finding_evidence", "event_id"),
    ("search_index_offsets", "last_id"),
}

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "20260810_0036_bigint_event_identifiers.py"


@pytest.fixture(scope="module", autouse=True)
def models_loaded():
    load_all_models()


def _load_migration():
    spec = importlib.util.spec_from_file_location("bigint_event_identifiers", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _column(table_name: str, column_name: str):
    return Base.metadata.tables[table_name].columns[column_name]


@pytest.mark.parametrize(("table_name", "column_name"), sorted(EVENT_IDENTIFIER_COLUMNS))
def test_event_identifier_columns_are_64_bit(table_name, column_name):
    column = _column(table_name, column_name)

    assert isinstance(column.type, BigInteger), (
        f"{table_name}.{column_name} stores a net_events identifier and must be BigInteger"
    )


def test_every_foreign_key_into_net_events_is_64_bit():
    offenders = []
    for table in Base.metadata.tables.values():
        for column in table.columns:
            for fk in column.foreign_keys:
                if fk.target_fullname != "net_events.id":
                    continue
                if not isinstance(column.type, BigInteger):
                    offenders.append(f"{table.name}.{column.name}")

    assert offenders == [], f"foreign keys into net_events.id must be BigInteger: {offenders}"


def test_migration_covers_every_known_identifier_column():
    migration = _load_migration()

    declared = {
        (table, column)
        for table, columns in migration.EVENT_IDENTIFIER_COLUMNS
        for column in columns
    }

    assert declared == EVENT_IDENTIFIER_COLUMNS


def test_migration_retypes_the_sequence_that_backs_the_primary_key():
    migration = _load_migration()

    assert migration.OWNED_SEQUENCES == (("net_events", "id"),)


def test_migration_groups_one_table_into_a_single_rewrite():
    migration = _load_migration()

    tables = [table for table, _ in migration.EVENT_IDENTIFIER_COLUMNS]

    assert len(tables) == len(set(tables))
    assert dict(migration.EVENT_IDENTIFIER_COLUMNS)["net_events"] == ("id", "bytes")


def test_the_hot_store_can_hold_a_flow_larger_than_two_gibibytes():
    column = _column("net_events", "bytes")

    assert isinstance(column.type, BigInteger)
    assert INT4_MAX < 4 * 1024**3
