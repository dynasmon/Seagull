from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.features.agents.models import AgentModel
from app.features.alerts.models import AlertModel
from app.features.exposure.models import ExposureAssetPostureModel
from app.features.inventory.models import AgentInventoryLatestModel
from app.features.network_topology import repository
from app.features.network_topology.classification import (
    classify_topology_ip,
    infer_subnet_cidr,
)
from app.features.network_topology.schemas import TopologyCoverageOut

logger = logging.getLogger("seagull.network_topology.projector")

_ALERT_WINDOW_HOURS = 48
_MAX_ALERT_ROWS = 2000
_MAX_AGENT_ROWS = 500
_STALE_AGENT_HOURS = 24 * 7


def project_topology(db: Session) -> TopologyCoverageOut:
    """Full topology projection from agents, inventory, alerts, and exposure.

    Marks existing nodes stale before projection, then re-upserts active ones.
    Bounded to avoid unbounded table scans.
    """
    coverage = TopologyCoverageOut()
    cidrs = settings.SEAGULL_INTERNAL_NETWORK_CIDRS or None
    now = datetime.now(timezone.utc)

    repository.mark_all_nodes_stale(db)

    agents = db.execute(
        select(AgentModel)
        .where(AgentModel.is_revoked.is_(False))
        .order_by(AgentModel.last_seen_at.desc())
        .limit(_MAX_AGENT_ROWS)
    ).scalars().all()
    coverage.agents_projected = len(agents)

    agent_nodes: dict[str, str] = {}

    for agent in agents:
        is_stale = _is_stale_agent(agent.last_seen_at, now)
        agent_node_key = _node_key("agent", agent.agent_id)
        label = str(agent.display_name or agent.agent_id)
        last_seen = _to_utc(agent.last_seen_at) or now

        repository.upsert_node(
            db,
            node_key=agent_node_key,
            node_type="agent",
            label=label,
            agent_id=agent.agent_id,
            ip=None,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=90,
            first_seen_at=_to_utc(agent.created_at) or now,
            last_seen_at=last_seen,
            extra_data={"is_stale_agent": is_stale},
        )
        agent_nodes[agent.agent_id] = agent_node_key

    inventory_rows = db.execute(
        select(AgentInventoryLatestModel)
        .order_by(AgentInventoryLatestModel.updated_at.desc())
        .limit(_MAX_AGENT_ROWS)
    ).scalars().all()
    coverage.agents_with_inventory = len(inventory_rows)

    subnet_seen: set[str] = set()

    for inv in inventory_rows:
        agent_id = str(inv.agent_id)
        os_data = inv.os or {}
        hostname = str(os_data.get("hostname") or agent_id)
        ip_addresses: list[str] = [
            str(ip).strip()
            for ip in (os_data.get("ip_addresses") or [])
            if str(ip or "").strip()
        ]
        last_seen = _to_utc(inv.updated_at) or now
        host_node_key = _node_key("host", agent_id, hostname)

        repository.upsert_node(
            db,
            node_key=host_node_key,
            node_type="host",
            label=hostname,
            agent_id=agent_id,
            ip=ip_addresses[0] if ip_addresses else None,
            cidr=None,
            port=None,
            protocol=None,
            severity="unknown",
            risk_score=0,
            confidence=85,
            first_seen_at=_to_utc(inv.collected_at) or now,
            last_seen_at=last_seen,
            extra_data={"hostname": hostname, "ip_addresses": ip_addresses[:20]},
        )

        agent_node_key = agent_nodes.get(agent_id)
        if agent_node_key:
            repository.upsert_edge(
                db,
                edge_key=_edge_key("same_agent", agent_node_key, host_node_key),
                source_node_key=agent_node_key,
                target_node_key=host_node_key,
                edge_type="same_agent",
                agent_id=agent_id,
                weight=1.0,
                confidence=90,
                severity="unknown",
                port=None,
                protocol=None,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={},
            )

        for ip in ip_addresses[:20]:
            coverage.interfaces_extracted += 1
            ip_info = classify_topology_ip(ip, internal_cidrs=cidrs)
            iface_node_key = _node_key("iface", agent_id, ip)

            repository.upsert_node(
                db,
                node_key=iface_node_key,
                node_type="interface",
                label=ip,
                agent_id=agent_id,
                ip=ip,
                cidr=None,
                port=None,
                protocol=None,
                severity="unknown",
                risk_score=0,
                confidence=80,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={"ip_scope": ip_info.get("scope"), "node_class": ip_info.get("node_class")},
            )

            repository.upsert_edge(
                db,
                edge_key=_edge_key("owns_interface", host_node_key, iface_node_key),
                source_node_key=host_node_key,
                target_node_key=iface_node_key,
                edge_type="owns_interface",
                agent_id=agent_id,
                weight=1.0,
                confidence=85,
                severity="unknown",
                port=None,
                protocol=None,
                first_seen_at=last_seen,
                last_seen_at=last_seen,
                extra_data={},
            )

            cidr = infer_subnet_cidr(ip)
            if cidr and cidr not in subnet_seen:
                subnet_seen.add(cidr)
                coverage.subnets_inferred += 1
                subnet_node_key = _node_key("subnet", cidr)
                repository.upsert_node(
                    db,
                    node_key=subnet_node_key,
                    node_type="subnet",
                    label=cidr,
                    agent_id=None,
                    ip=None,
                    cidr=cidr,
                    port=None,
                    protocol=None,
                    severity="unknown",
                    risk_score=0,
                    confidence=70,
                    first_seen_at=last_seen,
                    last_seen_at=last_seen,
                    extra_data={},
                )

            if cidr:
                subnet_node_key = _node_key("subnet", cidr)
                repository.upsert_edge(
                    db,
                    edge_key=_edge_key("member_of_subnet", iface_node_key, subnet_node_key),
                    source_node_key=iface_node_key,
                    target_node_key=subnet_node_key,
                    edge_type="member_of_subnet",
                    agent_id=agent_id,
                    weight=0.8,
                    confidence=70,
                    severity="unknown",
                    port=None,
                    protocol=None,
                    first_seen_at=last_seen,
                    last_seen_at=last_seen,
                    extra_data={},
                )

    _project_alert_edges(db, now=now, cidrs=cidrs, coverage=coverage)
    _project_exposure_edges(db, now=now, coverage=coverage, agent_nodes=agent_nodes)

    return coverage


def _project_alert_edges(
    db: Session,
    *,
    now: datetime,
    cidrs: list[str] | None,
    coverage: TopologyCoverageOut,
) -> None:
    since = now - timedelta(hours=_ALERT_WINDOW_HOURS)
    alerts = db.execute(
        select(
            AlertModel.src_ip,
            AlertModel.dst_ip,
            AlertModel.dst_port,
            AlertModel.app_proto,
            AlertModel.severity,
            AlertModel.created_at,
        )
        .where(
            AlertModel.created_at >= since,
            AlertModel.src_ip.isnot(None),
            AlertModel.dst_ip.isnot(None),
        )
        .order_by(AlertModel.created_at.desc())
        .limit(_MAX_ALERT_ROWS)
    ).all()

    for row in alerts:
        src_ip, dst_ip, dst_port, app_proto, severity, created_at = row
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

        edge_key = _edge_key("alert_related", src_key, dst_key)
        repository.upsert_edge(
            db,
            edge_key=edge_key,
            source_node_key=src_key,
            target_node_key=dst_key,
            edge_type="alert_related",
            agent_id=None,
            weight=_sev_weight(sev),
            confidence=75,
            severity=sev,
            port=dst_port,
            protocol=app_proto,
            first_seen_at=alert_ts,
            last_seen_at=alert_ts,
            extra_data={},
        )
        coverage.alert_edges_added += 1


def _project_exposure_edges(
    db: Session,
    *,
    now: datetime,
    coverage: TopologyCoverageOut,
    agent_nodes: dict[str, str],
) -> None:
    postures = db.execute(
        select(
            ExposureAssetPostureModel.agent_id,
            ExposureAssetPostureModel.asset_key,
            ExposureAssetPostureModel.severity,
            ExposureAssetPostureModel.risk_score,
            ExposureAssetPostureModel.last_seen_at,
        )
        .where(ExposureAssetPostureModel.agent_id.isnot(None))
        .order_by(ExposureAssetPostureModel.risk_score.desc())
        .limit(_MAX_AGENT_ROWS)
    ).all()

    for row in postures:
        agent_id, asset_key, severity, risk_score, last_seen = row
        agent_node_key = agent_nodes.get(str(agent_id or ""))
        if not agent_node_key:
            continue
        exposure_node_key = _node_key("exposure", str(asset_key))
        sev = str(severity or "unknown")
        ts = _to_utc(last_seen) or now

        repository.upsert_node(
            db,
            node_key=exposure_node_key,
            node_type="host",
            label=str(asset_key),
            agent_id=str(agent_id),
            ip=None,
            cidr=None,
            port=None,
            protocol=None,
            severity=sev,
            risk_score=int(risk_score or 0),
            confidence=80,
            first_seen_at=ts,
            last_seen_at=ts,
            extra_data={"exposure_asset_key": str(asset_key)},
        )

        repository.upsert_edge(
            db,
            edge_key=_edge_key("exposure_related", agent_node_key, exposure_node_key),
            source_node_key=agent_node_key,
            target_node_key=exposure_node_key,
            edge_type="exposure_related",
            agent_id=str(agent_id),
            weight=1.0,
            confidence=80,
            severity=sev,
            port=None,
            protocol=None,
            first_seen_at=ts,
            last_seen_at=ts,
            extra_data={"risk_score": int(risk_score or 0)},
        )
        coverage.exposure_edges_added += 1


def _node_key(*parts: str) -> str:
    raw = "topo:" + ":".join(str(p) for p in parts)
    if len(raw) <= 200:
        return raw
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"topo:{parts[0]}:{digest}"


def _edge_key(edge_type: str, src: str, dst: str) -> str:
    raw = f"{edge_type}::{src}::{dst}"
    if len(raw) <= 250:
        return raw
    digest = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return f"{edge_type}::{digest}"


def _ip_node_key(ip: str, ip_info: dict[str, Any]) -> str:
    node_class = ip_info.get("node_class", "unknown")
    return _node_key(node_class, ip)


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _is_stale_agent(last_seen: datetime | None, now: datetime) -> bool:
    if last_seen is None:
        return True
    ts = _to_utc(last_seen)
    return (now - ts).total_seconds() > _STALE_AGENT_HOURS * 3600


def _sev_to_score(severity: str) -> int:
    return {"critical": 90, "high": 70, "medium": 50, "low": 30, "informational": 10}.get(
        str(severity or "").lower(), 0
    )


def _sev_weight(severity: str) -> float:
    return {"critical": 3.0, "high": 2.0, "medium": 1.5, "low": 1.0, "informational": 0.5}.get(
        str(severity or "").lower(), 1.0
    )
