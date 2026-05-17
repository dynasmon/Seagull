from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import exists, func, not_, or_, select
from sqlalchemy.orm import Session

from app.features.network_topology.models import TopologyEdgeModel, TopologyNodeModel


def topology_insight_metrics(db: Session, *, since: datetime) -> dict[str, Any]:
    new_by_type_rows = db.execute(
        select(TopologyNodeModel.node_type, func.count(TopologyNodeModel.id))
        .where(TopologyNodeModel.first_seen_at >= since)
        .group_by(TopologyNodeModel.node_type)
    ).all()
    new_by_type: dict[str, int] = {str(r[0]): int(r[1]) for r in new_by_type_rows}

    flow_total = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(TopologyEdgeModel.edge_type == "observed_flow")
        ).scalar() or 0
    )
    internal_to_public = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                TopologyEdgeModel.edge_type == "observed_flow",
                TopologyEdgeModel.target_node_key.like("topo:external_ip:%"),
            )
        ).scalar() or 0
    )
    public_to_internal = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                TopologyEdgeModel.edge_type == "observed_flow",
                TopologyEdgeModel.source_node_key.like("topo:external_ip:%"),
            )
        ).scalar() or 0
    )
    internal_to_internal = max(0, flow_total - internal_to_public - public_to_internal)

    high_risk_edges = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                TopologyEdgeModel.severity.in_(["critical", "high"])
            )
        ).scalar() or 0
    )
    exposed_services = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(
                TopologyNodeModel.node_type == "service",
                TopologyNodeModel.alert_count > 0,
            )
        ).scalar() or 0
    )

    stale_by_type_rows = db.execute(
        select(TopologyNodeModel.node_type, func.count(TopologyNodeModel.id))
        .where(TopologyNodeModel.is_stale == 1)
        .group_by(TopologyNodeModel.node_type)
    ).all()
    stale_by_type: dict[str, int] = {str(r[0]): int(r[1]) for r in stale_by_type_rows}
    stale_agents = stale_by_type.get("agent", 0)
    stale_other = sum(v for k, v in stale_by_type.items() if k not in ("agent", "subnet"))

    noisy_nodes = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(
                TopologyNodeModel.event_count >= 500,
                TopologyNodeModel.node_type.not_in(["subnet"]),
            )
        ).scalar() or 0
    )
    nodes_with_alerts = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(
                TopologyNodeModel.alert_count > 0,
                TopologyNodeModel.node_type.not_in(["subnet", "service"]),
            )
        ).scalar() or 0
    )
    docker_node_count = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(TopologyNodeModel.node_type == "docker_network")
        ).scalar() or 0
    )
    nodes_with_exposure_findings = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(
                TopologyNodeModel.is_stale == 0,
                TopologyNodeModel.node_type.not_in(["subnet", "service"]),
                or_(
                    exists(
                        select(TopologyEdgeModel.id).where(
                            TopologyEdgeModel.edge_type == "exposure_related",
                            TopologyEdgeModel.source_node_key == TopologyNodeModel.node_key,
                        )
                    ),
                    exists(
                        select(TopologyEdgeModel.id).where(
                            TopologyEdgeModel.edge_type == "exposure_related",
                            TopologyEdgeModel.target_node_key == TopologyNodeModel.node_key,
                        )
                    ),
                ),
            )
        ).scalar() or 0
    )
    isolated_nodes = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(
                TopologyNodeModel.is_stale == 0,
                TopologyNodeModel.node_type.not_in(["subnet"]),
                not_(
                    exists(
                        select(TopologyEdgeModel.id).where(
                            or_(
                                TopologyEdgeModel.source_node_key == TopologyNodeModel.node_key,
                                TopologyEdgeModel.target_node_key == TopologyNodeModel.node_key,
                            )
                        )
                    )
                ),
            )
        ).scalar() or 0
    )

    last_flow_at = db.execute(
        select(func.max(TopologyEdgeModel.last_seen_at)).where(TopologyEdgeModel.edge_type == "observed_flow")
    ).scalar()
    last_alert_at = db.execute(
        select(func.max(TopologyEdgeModel.last_seen_at)).where(TopologyEdgeModel.edge_type == "alert_related")
    ).scalar()
    last_inventory_at = db.execute(
        select(func.max(TopologyNodeModel.last_seen_at)).where(TopologyNodeModel.node_type == "agent")
    ).scalar()

    return {
        "new_internal_hosts": new_by_type.get("host", 0) + new_by_type.get("interface", 0),
        "new_external_ips": new_by_type.get("external_ip", 0),
        "flow_edge_count": flow_total,
        "internal_to_internal": internal_to_internal,
        "internal_to_public": internal_to_public,
        "public_to_internal": public_to_internal,
        "high_risk_edges": high_risk_edges,
        "exposed_services": exposed_services,
        "stale_agents": stale_agents,
        "stale_other": stale_other,
        "noisy_nodes": noisy_nodes,
        "nodes_with_alerts": nodes_with_alerts,
        "docker_node_count": docker_node_count,
        "nodes_with_exposure_findings": nodes_with_exposure_findings,
        "isolated_nodes": isolated_nodes,
        "last_flow_at": last_flow_at,
        "last_alert_at": last_alert_at,
        "last_inventory_at": last_inventory_at,
    }

def topology_summary_metrics(db: Session) -> dict[str, Any]:
    total_nodes = int(db.execute(select(func.count(TopologyNodeModel.id))).scalar() or 0)
    total_edges = int(db.execute(select(func.count(TopologyEdgeModel.id))).scalar() or 0)
    stale_nodes = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(TopologyNodeModel.is_stale == 1)
        ).scalar()
        or 0
    )

    type_rows = db.execute(
        select(TopologyNodeModel.node_type, func.count(TopologyNodeModel.id))
        .group_by(TopologyNodeModel.node_type)
    ).all()
    by_type: dict[str, int] = {row[0]: int(row[1]) for row in type_rows}

    alert_edges = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                TopologyEdgeModel.edge_type == "alert_related"
            )
        ).scalar()
        or 0
    )
    exposure_edges = int(
        db.execute(
            select(func.count(TopologyEdgeModel.id)).where(
                TopologyEdgeModel.edge_type == "exposure_related"
            )
        ).scalar()
        or 0
    )

    return {
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "stale_node_count": stale_nodes,
        "by_type": by_type,
        "alert_edge_count": alert_edges,
        "exposure_edge_count": exposure_edges,
    }

def count_stale_nodes(db: Session) -> int:
    return int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(TopologyNodeModel.is_stale == 1)
        ).scalar()
        or 0
    )
