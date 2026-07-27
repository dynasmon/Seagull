from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.features.network_topology import repository
from app.features.network_topology.projection.exposure import _MAX_EXPOSURE_ROWS, _project_exposure_graph
from app.features.network_topology.projection.helpers import (
    _APP_PROTO_MAP,
    _STALE_AGENT_HOURS,
    _WELL_KNOWN_PORTS,
    _edge_key,
    _flow_edge_key,
    _ip_node_key,
    _is_stale_agent,
    _is_valid_ip,
    _matching_interface_network_cidr,
    _network_from_iface_cidrs,
    _node_key,
    _resolve_service_info,
    _sev_to_score,
    _sev_weight,
    _to_utc,
)
from app.features.network_topology.projection.inventory import (
    _MAX_AGENT_ROWS,
    _project_agents,
    _project_inventory,
    _project_ip_addresses_fallback,
    _project_network_context_interfaces,
    _project_network_context_neighbors_and_routes,
)
from app.features.network_topology.projection.traffic import (
    _MAX_ALERT_ROWS,
    _project_alert_edges,
    _project_flow_edges,
)
from app.features.network_topology.schemas import TopologyCoverageOut

logger = logging.getLogger("seagull.network_topology.projector")

__all__ = [
    "_APP_PROTO_MAP",
    "_MAX_AGENT_ROWS",
    "_MAX_ALERT_ROWS",
    "_MAX_EXPOSURE_ROWS",
    "_STALE_AGENT_HOURS",
    "_WELL_KNOWN_PORTS",
    "_edge_key",
    "_flow_edge_key",
    "_ip_node_key",
    "_is_stale_agent",
    "_is_valid_ip",
    "_matching_interface_network_cidr",
    "_network_from_iface_cidrs",
    "_node_key",
    "_project_agents",
    "_project_alert_edges",
    "_project_exposure_graph",
    "_project_flow_edges",
    "_project_inventory",
    "_project_ip_addresses_fallback",
    "_project_network_context_interfaces",
    "_project_network_context_neighbors_and_routes",
    "_resolve_service_info",
    "_sev_to_score",
    "_sev_weight",
    "_to_utc",
    "project_topology",
]


def project_topology(
    db: Session,
    *,
    window_minutes: int = 1440,
    max_events_per_run: int = 5000,
) -> TopologyCoverageOut:
    coverage = TopologyCoverageOut()
    cidrs = settings.SEAGULL_INTERNAL_NETWORK_CIDRS or None
    now = datetime.now(timezone.utc)

    repository.mark_all_nodes_stale(db)

    agent_nodes = _project_agents(db, now=now, coverage=coverage)
    _project_inventory(db, now=now, cidrs=cidrs, coverage=coverage, agent_nodes=agent_nodes)
    _project_flow_edges(db, now=now, cidrs=cidrs, coverage=coverage, window_minutes=window_minutes, max_events_per_run=max_events_per_run)
    _project_alert_edges(db, now=now, cidrs=cidrs, coverage=coverage, window_minutes=window_minutes)
    _project_exposure_graph(db, now=now, coverage=coverage, agent_nodes=agent_nodes)
    repository.release_external_node_ownership(db)

    coverage.stale_nodes_marked = repository.count_stale_nodes(db)
    return coverage
