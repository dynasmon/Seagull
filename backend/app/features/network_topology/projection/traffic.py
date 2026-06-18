from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.features.alerts import public as alerts_public
from app.features.events.models import NetEventModel
from app.features.network_topology import repository
from app.features.network_topology.classification import classify_topology_ip
from app.features.network_topology.projection.helpers import (
    _edge_key,
    _flow_edge_key,
    _ip_node_key,
    _node_key,
    _resolve_service_info,
    _sev_to_score,
    _sev_weight,
    _to_utc,
)
from app.features.network_topology.schemas import TopologyCoverageOut

_MAX_ALERT_ROWS = 2000


def _project_flow_edges(
    db: Session,
    *,
    now: datetime,
    cidrs: list[str] | None,
    coverage: TopologyCoverageOut,
    window_minutes: int = 1440,
    max_events_per_run: int = 5000,
) -> None:
    since = now - timedelta(minutes=window_minutes)
    max_rows = max(100, int(max_events_per_run))

    flow_rows = db.execute(
        select(
            NetEventModel.agent_id,
            NetEventModel.src_ip,
            NetEventModel.dst_ip,
            NetEventModel.dst_port,
            NetEventModel.proto,
            func.max(NetEventModel.app_proto).label("app_proto"),
            func.count(NetEventModel.id).label("flow_count"),
            func.max(NetEventModel.timestamp).label("last_seen"),
            func.min(NetEventModel.timestamp).label("first_seen"),
        )
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.src_ip.isnot(None),
            NetEventModel.dst_ip.isnot(None),
        )
        .group_by(
            NetEventModel.agent_id,
            NetEventModel.src_ip,
            NetEventModel.dst_ip,
            NetEventModel.dst_port,
            NetEventModel.proto,
        )
        .order_by(func.count(NetEventModel.id).desc())
        .limit(max_rows)
    ).all()

    for row in flow_rows:
        agent_id, src_ip, dst_ip, dst_port, proto, app_proto, flow_count, last_seen, first_seen = row

        src_info = classify_topology_ip(src_ip, internal_cidrs=cidrs)
        dst_info = classify_topology_ip(dst_ip, internal_cidrs=cidrs)
        src_key = _ip_node_key(src_ip, src_info)
        dst_key = _ip_node_key(dst_ip, dst_info)
        edge_ts = _to_utc(last_seen) or now
        flow_first = _to_utc(first_seen) or now
        agent_id_str = str(agent_id) if agent_id else None

        repository.upsert_node(
            db,
            node_key=src_key,
            node_type=src_info.get("node_class", "unknown"),
            label=src_ip,
            agent_id=agent_id_str,
            ip=src_ip,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=70,
            first_seen_at=flow_first,
            last_seen_at=edge_ts,
            extra_data={"ip_scope": src_info.get("scope")},
        )

        repository.upsert_node(
            db,
            node_key=dst_key,
            node_type=dst_info.get("node_class", "unknown"),
            label=dst_ip,
            agent_id=None,
            ip=dst_ip,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=65,
            first_seen_at=flow_first,
            last_seen_at=edge_ts,
            extra_data={"ip_scope": dst_info.get("scope")},
        )

        flow_edge_key = _flow_edge_key(src_key, dst_key, dst_port, proto)
        repository.upsert_edge(
            db,
            edge_key=flow_edge_key,
            source_node_key=src_key,
            target_node_key=dst_key,
            edge_type="observed_flow",
            agent_id=agent_id_str,
            weight=min(float(flow_count) / 10.0, 5.0),
            confidence=70,
            severity="unknown",
            port=dst_port,
            protocol=proto,
            first_seen_at=flow_first,
            last_seen_at=edge_ts,
            extra_data={"flow_count": int(flow_count)},
        )
        coverage.flow_edges_added += 1

        # Create service node for inbound flows to internal hosts with a port
        if (
            dst_port
            and dst_info.get("node_class") in ("host", "interface")
            and dst_info.get("scope") in ("private_address", "internal_network")
        ):
            svc_node_key = _node_key(
                "service", dst_ip, str(proto or ""), str(dst_port)
            )
            svc_info = _resolve_service_info(dst_port, proto, str(app_proto or "") or None)
            repository.upsert_node(
                db,
                node_key=svc_node_key,
                node_type="service",
                label=svc_info["name"],
                agent_id=agent_id_str,
                ip=dst_ip,
                cidr=None,
                port=dst_port,
                protocol=proto,
                severity="unknown",
                risk_score=0,
                confidence=75,
                first_seen_at=flow_first,
                last_seen_at=edge_ts,
                extra_data={
                    "flow_count": int(flow_count),
                    "service_name": svc_info["name"],
                    "service_category": svc_info["category"],
                    "dst_ip": dst_ip,
                    "app_proto": str(app_proto or ""),
                },
            )
            repository.upsert_edge(
                db,
                edge_key=_edge_key("listens_on", dst_key, svc_node_key),
                source_node_key=dst_key,
                target_node_key=svc_node_key,
                edge_type="listens_on",
                agent_id=agent_id_str,
                weight=1.0,
                confidence=70,
                severity="unknown",
                port=dst_port,
                protocol=proto,
                first_seen_at=flow_first,
                last_seen_at=edge_ts,
                extra_data={},
            )
            coverage.services_projected += 1

def _project_alert_edges(
    db: Session,
    *,
    now: datetime,
    cidrs: list[str] | None,
    coverage: TopologyCoverageOut,
    window_minutes: int = 1440,
) -> None:
    alert_window_minutes = max(window_minutes, 2 * 60)
    since = now - timedelta(minutes=alert_window_minutes)
    alerts = alerts_public.list_alert_flows_since(db, since=since, limit=_MAX_ALERT_ROWS)

    for row in alerts:
        src_ip = row.src_ip
        dst_ip = row.dst_ip
        dst_port = row.dst_port
        severity = row.severity
        created_at = row.created_at
        src_info = classify_topology_ip(src_ip, internal_cidrs=cidrs)
        dst_info = classify_topology_ip(dst_ip, internal_cidrs=cidrs)
        src_key = _ip_node_key(src_ip, src_info)
        dst_key = _ip_node_key(dst_ip, dst_info)
        alert_ts = _to_utc(created_at) or now
        sev = str(severity or "unknown")

        for ip, info, nk in [(src_ip, src_info, src_key), (dst_ip, dst_info, dst_key)]:
            repository.upsert_node(
                db,
                node_key=nk,
                node_type=info.get("node_class", "unknown"),
                label=ip,
                agent_id=None,
                ip=ip,
                cidr=None,
                port=None,
                protocol=None,
                severity=sev,
                risk_score=_sev_to_score(sev),
                confidence=60,
                first_seen_at=alert_ts,
                last_seen_at=alert_ts,
                extra_data={"ip_scope": info.get("scope")},
            )

        repository.upsert_edge(
            db,
            edge_key=_edge_key("alert_related", src_key, dst_key),
            source_node_key=src_key,
            target_node_key=dst_key,
            edge_type="alert_related",
            agent_id=None,
            weight=_sev_weight(sev),
            confidence=75,
            severity=sev,
            port=dst_port,
            protocol=None,
            first_seen_at=alert_ts,
            last_seen_at=alert_ts,
            extra_data={},
        )
        coverage.alert_edges_added += 1
