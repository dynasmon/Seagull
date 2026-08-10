import importlib.util
import os
from pathlib import Path

os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:seagull@127.0.0.1:5432/seagull")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import pytest
from sqlalchemy import BigInteger

from app.core.db import Base
from app.core.db.model_registry import load_all_models

REBUILT_GRAPH_TABLES = {
    "network_topology_nodes",
    "network_topology_edges",
    "network_topology_observations",
    "network_topology_snapshots",
    "exposure_asset_posture",
    "exposure_nodes",
    "exposure_edges",
    "exposure_findings",
    "exposure_score_history",
}

MIGRATION_PATH = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "20260810_0037_bigint_graph_identifiers.py"


@pytest.fixture(scope="module", autouse=True)
def models_loaded():
    load_all_models()


def _load_migration():
    spec = importlib.util.spec_from_file_location("bigint_graph_identifiers", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("table_name", sorted(REBUILT_GRAPH_TABLES))
def test_rebuilt_graph_tables_have_64_bit_identities(table_name):
    column = Base.metadata.tables[table_name].columns["id"]

    assert isinstance(column.type, BigInteger), (
        f"{table_name} is rebuilt every worker cycle, so its identity burns sequence values "
        "independently of how many rows it stores and must be BigInteger"
    )


def test_migration_covers_every_rebuilt_graph_table():
    migration = _load_migration()

    assert set(migration.REBUILT_GRAPH_TABLES) == REBUILT_GRAPH_TABLES


def test_no_table_in_the_graph_features_keeps_a_32_bit_identity():
    offenders = []
    for table in Base.metadata.tables.values():
        if not table.name.startswith(("network_topology_", "exposure_")):
            continue
        column = table.columns.get("id")
        if column is None or not column.primary_key:
            continue
        if not isinstance(column.type, BigInteger):
            offenders.append(table.name)

    assert offenders == [], f"graph feature tables must not keep a 32-bit identity: {offenders}"
