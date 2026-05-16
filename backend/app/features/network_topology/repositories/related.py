from __future__ import annotations

from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.attack_chain.models import AttackChainCaseModel
from app.features.events.models import NetEventModel
from app.features.exposure.models import ExposureFindingModel
from app.features.network_topology.models import TopologyEdgeModel, TopologyNodeModel


def list_related_flows_for_node(db: Session, *, node: TopologyNodeModel, limit: int = 10) -> list[NetEventModel]:
    conditions = _flow_conditions_for_node(node)
    if not conditions:
        return []
    stmt = (
        select(NetEventModel)
        .where(*conditions)
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def list_related_flows_for_edge(
    db: Session,
    *,
    edge: TopologyEdgeModel,
    source_node: TopologyNodeModel | None,
    target_node: TopologyNodeModel | None,
    limit: int = 10,
) -> list[NetEventModel]:
    conditions = _flow_conditions_for_edge(edge, source_node, target_node)
    if not conditions:
        return []
    stmt = (
        select(NetEventModel)
        .where(*conditions)
        .order_by(NetEventModel.timestamp.desc(), NetEventModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def edge_flow_metrics(
    db: Session,
    *,
    edge: TopologyEdgeModel,
    source_node: TopologyNodeModel | None,
    target_node: TopologyNodeModel | None,
    app_proto_limit: int = 12,
) -> tuple[int, list[str]]:
    conditions = _flow_conditions_for_edge(edge, source_node, target_node)
    if not conditions:
        return 0, []

    total_bytes = int(
        db.execute(
            select(func.coalesce(func.sum(NetEventModel.bytes), 0)).where(*conditions)
        ).scalar()
        or 0
    )

    proto_expr = func.lower(NetEventModel.app_proto)
    rows = db.execute(
        select(proto_expr, func.count(NetEventModel.id))
        .where(
            *conditions,
            NetEventModel.app_proto.is_not(None),
            NetEventModel.app_proto != "",
        )
        .group_by(proto_expr)
        .order_by(func.count(NetEventModel.id).desc(), proto_expr.asc())
        .limit(min(int(app_proto_limit), 50))
    ).all()

    protocols: list[str] = []
    seen: set[str] = set()
    for raw, _count in rows:
        proto = _clean_text(raw).lower()
        if not proto or proto in seen:
            continue
        seen.add(proto)
        protocols.append(proto)
    return total_bytes, protocols

def list_related_alerts_for_node(db: Session, *, node: TopologyNodeModel, limit: int = 10) -> list[AlertModel]:
    conditions = _alert_conditions_for_node(node)
    if not conditions:
        return []
    stmt = (
        select(AlertModel)
        .where(*conditions)
        .order_by(AlertModel.created_at.desc(), AlertModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def list_related_alerts_for_edge(
    db: Session,
    *,
    edge: TopologyEdgeModel,
    source_node: TopologyNodeModel | None,
    target_node: TopologyNodeModel | None,
    limit: int = 10,
) -> list[AlertModel]:
    conditions = _alert_conditions_for_edge(edge, source_node, target_node)
    if not conditions:
        return []
    stmt = (
        select(AlertModel)
        .where(*conditions)
        .order_by(AlertModel.created_at.desc(), AlertModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def list_related_exposure_findings_for_node(
    db: Session,
    *,
    node: TopologyNodeModel,
    limit: int = 10,
) -> list[ExposureFindingModel]:
    conditions = _exposure_conditions_for_node(node)
    if not conditions:
        return []
    stmt = (
        select(ExposureFindingModel)
        .where(or_(*conditions))
        .order_by(ExposureFindingModel.last_seen_at.desc(), ExposureFindingModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def list_related_exposure_findings_for_edge(
    db: Session,
    *,
    source_node: TopologyNodeModel | None,
    target_node: TopologyNodeModel | None,
    limit: int = 10,
) -> list[ExposureFindingModel]:
    conditions: list[Any] = []
    for node in (source_node, target_node):
        if node is None:
            continue
        conditions.extend(_exposure_conditions_for_node(node))
    if not conditions:
        return []
    stmt = (
        select(ExposureFindingModel)
        .where(or_(*conditions))
        .order_by(ExposureFindingModel.last_seen_at.desc(), ExposureFindingModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def list_related_attack_chain_cases_for_node(
    db: Session,
    *,
    node: TopologyNodeModel,
    limit: int = 10,
) -> list[AttackChainCaseModel]:
    conditions = _attack_chain_conditions_for_node(node)
    if not conditions:
        return []
    stmt = (
        select(AttackChainCaseModel)
        .where(or_(*conditions))
        .order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def list_related_attack_chain_cases_for_edge(
    db: Session,
    *,
    source_node: TopologyNodeModel | None,
    target_node: TopologyNodeModel | None,
    limit: int = 10,
) -> list[AttackChainCaseModel]:
    conditions: list[Any] = []
    for node in (source_node, target_node):
        if node is None:
            continue
        conditions.extend(_attack_chain_conditions_for_node(node))
    if not conditions:
        return []
    stmt = (
        select(AttackChainCaseModel)
        .where(or_(*conditions))
        .order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
        .limit(min(int(limit), 50))
    )
    return db.execute(stmt).scalars().all()

def _clean_text(value: Any) -> str:
    return str(value or "").strip()

def _flow_conditions_for_node(node: TopologyNodeModel) -> list[Any]:
    ip = _clean_text(node.ip)
    agent_id = _clean_text(node.agent_id)
    node_type = _clean_text(node.node_type)
    conditions: list[Any] = []

    if node_type == "service":
        if ip:
            conditions.append(NetEventModel.dst_ip == ip)
        if node.port is not None:
            conditions.append(NetEventModel.dst_port == int(node.port))
        if _clean_text(node.protocol):
            conditions.append(func.lower(NetEventModel.proto) == _clean_text(node.protocol).lower())
        if agent_id:
            conditions.append(NetEventModel.agent_id == agent_id)
        return conditions

    if ip:
        conditions.append(or_(NetEventModel.src_ip == ip, NetEventModel.dst_ip == ip))
        if agent_id and node_type in {"host", "interface", "docker_network"}:
            conditions.append(NetEventModel.agent_id == agent_id)
        return conditions

    if agent_id:
        conditions.append(NetEventModel.agent_id == agent_id)
    return conditions

def _flow_conditions_for_edge(
    edge: TopologyEdgeModel,
    source_node: TopologyNodeModel | None,
    target_node: TopologyNodeModel | None,
) -> list[Any]:
    src_ip = _clean_text(getattr(source_node, "ip", None))
    dst_ip = _clean_text(getattr(target_node, "ip", None))
    conditions: list[Any] = []

    if src_ip and dst_ip:
        if edge.edge_type == "observed_flow":
            conditions.append(and_(NetEventModel.src_ip == src_ip, NetEventModel.dst_ip == dst_ip))
        else:
            conditions.append(
                or_(
                    and_(NetEventModel.src_ip == src_ip, NetEventModel.dst_ip == dst_ip),
                    and_(NetEventModel.src_ip == dst_ip, NetEventModel.dst_ip == src_ip),
                )
            )
    elif src_ip or dst_ip:
        ip = src_ip or dst_ip
        conditions.append(or_(NetEventModel.src_ip == ip, NetEventModel.dst_ip == ip))

    if edge.port is not None:
        conditions.append(NetEventModel.dst_port == int(edge.port))
    if _clean_text(edge.protocol):
        conditions.append(func.lower(NetEventModel.proto) == _clean_text(edge.protocol).lower())
    if _clean_text(edge.agent_id):
        conditions.append(NetEventModel.agent_id == _clean_text(edge.agent_id))
    return conditions

def _alert_conditions_for_node(node: TopologyNodeModel) -> list[Any]:
    ip = _clean_text(node.ip)
    agent_id = _clean_text(node.agent_id)
    conditions: list[Any] = []
    if ip:
        conditions.append(or_(AlertModel.src_ip == ip, AlertModel.dst_ip == ip))
        return conditions
    if agent_id:
        conditions.append(AlertModel.details["agent_id"].astext == agent_id)
    return conditions

def _alert_conditions_for_edge(
    edge: TopologyEdgeModel,
    source_node: TopologyNodeModel | None,
    target_node: TopologyNodeModel | None,
) -> list[Any]:
    src_ip = _clean_text(getattr(source_node, "ip", None))
    dst_ip = _clean_text(getattr(target_node, "ip", None))
    conditions: list[Any] = []
    if src_ip and dst_ip:
        conditions.append(
            or_(
                and_(AlertModel.src_ip == src_ip, AlertModel.dst_ip == dst_ip),
                and_(AlertModel.src_ip == dst_ip, AlertModel.dst_ip == src_ip),
            )
        )
    elif src_ip or dst_ip:
        ip = src_ip or dst_ip
        conditions.append(or_(AlertModel.src_ip == ip, AlertModel.dst_ip == ip))
    if edge.port is not None:
        conditions.append(AlertModel.dst_port == int(edge.port))
    if _clean_text(edge.agent_id):
        conditions.append(AlertModel.details["agent_id"].astext == _clean_text(edge.agent_id))
    return conditions

def _exposure_conditions_for_node(node: TopologyNodeModel) -> list[Any]:
    metadata = node.extra_data if isinstance(node.extra_data, dict) else {}
    asset_key = _clean_text(metadata.get("exposure_asset_key"))
    agent_id = _clean_text(node.agent_id)
    conditions: list[Any] = []
    if asset_key:
        conditions.append(ExposureFindingModel.asset_key == asset_key)
    if agent_id:
        conditions.append(ExposureFindingModel.agent_id == agent_id)
    return conditions

def _attack_chain_conditions_for_node(node: TopologyNodeModel) -> list[Any]:
    ip = _clean_text(node.ip)
    agent_id = _clean_text(node.agent_id)
    conditions: list[Any] = []
    if ip:
        conditions.append(AttackChainCaseModel.suspect_ip == ip)
    if agent_id:
        conditions.append(AttackChainCaseModel.agent_id == agent_id)
    return conditions
