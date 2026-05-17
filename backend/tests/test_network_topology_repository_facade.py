from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://seagull:test@127.0.0.1:5432/seagull_test")

from app.features.network_topology import repository
from app.features.network_topology.repositories import graph, metrics, writes


def test_repository_facade_reexports_split_implementations() -> None:
    assert repository.list_nodes is graph.list_nodes
    assert repository.list_observations_page is graph.list_observations_page
    assert repository.topology_summary_metrics is metrics.topology_summary_metrics
    assert repository.mark_all_nodes_stale is writes.mark_all_nodes_stale
