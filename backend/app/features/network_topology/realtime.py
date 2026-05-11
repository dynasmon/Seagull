from __future__ import annotations

import logging

logger = logging.getLogger("seagull.network_topology.realtime")


def graph_nodes_hard_limit() -> int:
    return 2000


def graph_edges_hard_limit() -> int:
    return 3000


def publish_topology_updated(*, projected_nodes: int, projected_edges: int) -> None:
    logger.debug(
        "topology_updated nodes=%d edges=%d",
        projected_nodes,
        projected_edges,
    )
