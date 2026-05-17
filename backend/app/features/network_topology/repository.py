from __future__ import annotations

"""Compatibility facade for network-topology persistence and query helpers.

The implementation is split by concern under ``repositories/`` so callers can keep
using ``network_topology.repository`` while the feature remains navigable.
"""

from app.features.network_topology.repositories.constants import _MAX_GRAPH_FETCH, _MAX_PAGE
from app.features.network_topology.repositories.graph import (
    count_observations_for_edge,
    count_observations_for_node,
    evidence_sources_for_edge,
    evidence_sources_for_node,
    get_edge,
    get_latest_snapshot,
    get_node,
    list_connected_node_keys,
    list_edges,
    list_edges_for_node,
    list_nodes,
    list_nodes_by_keys,
    list_observations_for_edge,
    list_observations_for_node,
    list_observations_page,
    list_subnet_nodes_page,
)
from app.features.network_topology.repositories.metrics import (
    count_stale_nodes,
    topology_insight_metrics,
    topology_summary_metrics,
)
from app.features.network_topology.repositories.related import (
    _alert_conditions_for_edge,
    _alert_conditions_for_node,
    _attack_chain_conditions_for_node,
    _clean_text,
    _exposure_conditions_for_node,
    _flow_conditions_for_edge,
    _flow_conditions_for_node,
    edge_flow_metrics,
    list_related_alerts_for_edge,
    list_related_alerts_for_node,
    list_related_attack_chain_cases_for_edge,
    list_related_attack_chain_cases_for_node,
    list_related_exposure_findings_for_edge,
    list_related_exposure_findings_for_node,
    list_related_flows_for_edge,
    list_related_flows_for_node,
)
from app.features.network_topology.repositories.subnets import (
    _subnet_member_keys_subquery,
    _subnet_related_edge_filter,
    count_edges_for_subnet,
    count_observations_for_subnet,
    count_subnet_member_nodes,
    get_subnet_node_by_cidr,
    list_edges_for_subnet,
    list_observations_for_subnet,
    list_subnet_member_nodes,
    subnet_member_metrics,
)
from app.features.network_topology.repositories.writes import (
    insert_observation,
    mark_all_nodes_stale,
    upsert_edge,
    upsert_node,
    upsert_snapshot,
)

_MAX_PAGE = 200
_MAX_GRAPH_FETCH = 2000


def upsert_node(
    db: Session,
    *,
    node_key: str,
    node_type: str,
    label: str,
    agent_id: str | None,
    ip: str | None,
    cidr: str | None,
    port: int | None,
    protocol: str | None,
    severity: str,
    risk_score: int,
    confidence: int,
    first_seen_at: datetime,
    last_seen_at: datetime,
    extra_data: dict[str, Any],
    event_count: int | None = None,
    alert_count: int | None = None,
    observation_count: int | None = None,
) -> TopologyNodeModel:
    now = datetime.now(timezone.utc)
    values = {
        "node_key": node_key,
        "node_type": node_type,
        "label": label,
        "agent_id": agent_id,
        "ip": ip,
        "cidr": cidr,
        "port": port,
        "protocol": protocol,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_stale": 0,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "updated_at": now,
        "extra_data": extra_data,
    }
    update_values = {
        "label": label,
        "ip": ip,
        "cidr": cidr,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_stale": 0,
        "last_seen_at": last_seen_at,
        "updated_at": now,
        "extra_data": extra_data,
    }
    if event_count is not None:
        values["event_count"] = int(event_count)
        update_values["event_count"] = func.greatest(TopologyNodeModel.event_count, int(event_count))
    if alert_count is not None:
        values["alert_count"] = int(alert_count)
        update_values["alert_count"] = func.greatest(TopologyNodeModel.alert_count, int(alert_count))
    if observation_count is not None:
        values["observation_count"] = int(observation_count)
        update_values["observation_count"] = func.greatest(TopologyNodeModel.observation_count, int(observation_count))
    stmt = (
        pg_insert(TopologyNodeModel)
        .values(**values)
        .on_conflict_do_update(
            index_elements=["node_key"],
            set_=update_values,
        )
        .returning(TopologyNodeModel)
    )
    return db.execute(stmt).scalars().one()


def upsert_edge(
    db: Session,
    *,
    edge_key: str,
    source_node_key: str,
    target_node_key: str,
    edge_type: str,
    agent_id: str | None,
    weight: float,
    confidence: int,
    severity: str,
    port: int | None,
    protocol: str | None,
    first_seen_at: datetime,
    last_seen_at: datetime,
    extra_data: dict[str, Any],
    event_count: int | None = None,
    alert_count: int | None = None,
) -> TopologyEdgeModel:
    now = datetime.now(timezone.utc)
    values = {
        "edge_key": edge_key,
        "source_node_key": source_node_key,
        "target_node_key": target_node_key,
        "edge_type": edge_type,
        "agent_id": agent_id,
        "weight": weight,
        "confidence": confidence,
        "severity": severity,
        "port": port,
        "protocol": protocol,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "updated_at": now,
        "extra_data": extra_data,
    }
    update_values = {
        "weight": weight,
        "confidence": confidence,
        "severity": severity,
        "last_seen_at": last_seen_at,
        "updated_at": now,
        "extra_data": extra_data,
    }
    if event_count is not None:
        values["event_count"] = int(event_count)
        update_values["event_count"] = func.greatest(TopologyEdgeModel.event_count, int(event_count))
    if alert_count is not None:
        values["alert_count"] = int(alert_count)
        update_values["alert_count"] = func.greatest(TopologyEdgeModel.alert_count, int(alert_count))
    stmt = (
        pg_insert(TopologyEdgeModel)
        .values(**values)
        .on_conflict_do_update(
            index_elements=["edge_key"],
            set_=update_values,
        )
        .returning(TopologyEdgeModel)
    )
    return db.execute(stmt).scalars().one()


def insert_observation(
    db: Session,
    *,
    node_key: str,
    edge_key: str | None,
    agent_id: str | None,
    source_type: str,
    source_id: str | None,
    observed_at: datetime,
    summary: str,
    raw_context: dict[str, Any],
) -> TopologyObservationModel:
    row = TopologyObservationModel(
        node_key=node_key,
        edge_key=edge_key,
        agent_id=agent_id,
        source_type=source_type,
        source_id=source_id,
        observed_at=observed_at,
        summary=summary,
        raw_context=raw_context,
    )
    db.add(row)
    return row


def upsert_snapshot(
    db: Session,
    *,
    snapshot_key: str,
    node_count: int,
    edge_count: int,
    agent_count: int,
    subnet_count: int,
    external_ip_count: int,
    coverage: dict[str, Any],
    metrics: dict[str, Any],
) -> TopologySnapshotModel:
    now = datetime.now(timezone.utc)
    stmt = (
        pg_insert(TopologySnapshotModel)
        .values(
            snapshot_key=snapshot_key,
            node_count=node_count,
            edge_count=edge_count,
            agent_count=agent_count,
            subnet_count=subnet_count,
            external_ip_count=external_ip_count,
            created_at=now,
            coverage=coverage,
            metrics=metrics,
        )
        .on_conflict_do_update(
            index_elements=["snapshot_key"],
            set_={
                "node_count": node_count,
                "edge_count": edge_count,
                "agent_count": agent_count,
                "subnet_count": subnet_count,
                "external_ip_count": external_ip_count,
                "created_at": now,
                "coverage": coverage,
                "metrics": metrics,
            },
        )
        .returning(TopologySnapshotModel)
    )
    return db.execute(stmt).scalars().one()


def get_node(db: Session, node_key: str) -> TopologyNodeModel | None:
    return db.execute(
        select(TopologyNodeModel).where(TopologyNodeModel.node_key == node_key)
    ).scalars().first()


def get_edge(db: Session, edge_key: str) -> TopologyEdgeModel | None:
    return db.execute(
        select(TopologyEdgeModel).where(TopologyEdgeModel.edge_key == edge_key)
    ).scalars().first()


def get_latest_snapshot(db: Session) -> TopologySnapshotModel | None:
    return db.execute(
        select(TopologySnapshotModel)
        .order_by(TopologySnapshotModel.created_at.desc(), TopologySnapshotModel.id.desc())
        .limit(1)
    ).scalars().first()


def list_nodes(
    db: Session,
    *,
    agent_id: str | None = None,
    node_types: Sequence[str] | None = None,
    ip_scope: str | None = None,
    min_confidence: int = 1,
    include_stale: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int,
) -> list[TopologyNodeModel]:
    limit = min(int(limit), _MAX_GRAPH_FETCH)
    stmt = select(TopologyNodeModel).where(
        TopologyNodeModel.confidence >= int(min_confidence),
    )
    if not include_stale:
        stmt = stmt.where(TopologyNodeModel.is_stale == 0)
    if agent_id:
        stmt = stmt.where(TopologyNodeModel.agent_id == agent_id)
    if node_types:
        stmt = stmt.where(TopologyNodeModel.node_type.in_(list(node_types)))
    if ip_scope:
        stmt = stmt.where(TopologyNodeModel.extra_data["ip_scope"].astext == ip_scope)
    if since is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at <= until)
    stmt = stmt.order_by(
        TopologyNodeModel.risk_score.desc(),
        TopologyNodeModel.confidence.desc(),
        TopologyNodeModel.id.desc(),
    )
    return db.execute(stmt.limit(limit)).scalars().all()


def list_edges(
    db: Session,
    *,
    agent_id: str | None = None,
    edge_types: Sequence[str] | None = None,
    min_confidence: int = 1,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int,
) -> list[TopologyEdgeModel]:
    limit = min(int(limit), _MAX_GRAPH_FETCH)
    stmt = select(TopologyEdgeModel).where(
        TopologyEdgeModel.confidence >= int(min_confidence),
    )
    if agent_id:
        stmt = stmt.where(TopologyEdgeModel.agent_id == agent_id)
    if edge_types:
        stmt = stmt.where(TopologyEdgeModel.edge_type.in_(list(edge_types)))
    if since is not None:
        stmt = stmt.where(TopologyEdgeModel.last_seen_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyEdgeModel.last_seen_at <= until)
    stmt = stmt.order_by(
        TopologyEdgeModel.confidence.desc(),
        TopologyEdgeModel.weight.desc(),
        TopologyEdgeModel.id.desc(),
    )
    return db.execute(stmt.limit(limit)).scalars().all()


def list_edges_for_node(
    db: Session,
    *,
    node_key: str,
    limit: int = 50,
) -> list[TopologyEdgeModel]:
    limit = min(int(limit), _MAX_PAGE)
    stmt = (
        select(TopologyEdgeModel)
        .where(
            or_(
                TopologyEdgeModel.source_node_key == node_key,
                TopologyEdgeModel.target_node_key == node_key,
            )
        )
        .order_by(TopologyEdgeModel.confidence.desc(), TopologyEdgeModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def list_connected_node_keys(
    db: Session,
    *,
    node_key: str,
    limit: int = 50,
) -> list[str]:
    edges = list_edges_for_node(db, node_key=node_key, limit=limit)
    keys: list[str] = []
    seen: set[str] = set()
    for edge in edges:
        for k in (edge.source_node_key, edge.target_node_key):
            if k != node_key and k not in seen:
                seen.add(k)
                keys.append(k)
    return keys


def list_nodes_by_keys(
    db: Session,
    *,
    node_keys: Sequence[str],
) -> list[TopologyNodeModel]:
    if not node_keys:
        return []
    stmt = select(TopologyNodeModel).where(TopologyNodeModel.node_key.in_(list(node_keys)))
    return db.execute(stmt).scalars().all()


def list_observations_page(
    db: Session,
    *,
    page_size: int,
    node_key: str | None,
    agent_id: str | None,
    source_type: str | None,
    since: datetime | None,
    until: datetime | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[TopologyObservationModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = select(TopologyObservationModel).order_by(
        TopologyObservationModel.observed_at.desc(),
        TopologyObservationModel.id.desc(),
    )
    if node_key:
        stmt = stmt.where(TopologyObservationModel.node_key == node_key)
    if agent_id:
        stmt = stmt.where(TopologyObservationModel.agent_id == agent_id)
    if source_type:
        stmt = stmt.where(TopologyObservationModel.source_type == source_type)
    if since is not None:
        stmt = stmt.where(TopologyObservationModel.observed_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyObservationModel.observed_at <= until)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                TopologyObservationModel.observed_at < c_ts,
                and_(
                    TopologyObservationModel.observed_at == c_ts,
                    TopologyObservationModel.id < c_id,
                ),
            )
        )
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def list_observations_for_node(
    db: Session,
    *,
    node_key: str,
    limit: int = 20,
) -> list[TopologyObservationModel]:
    limit = min(int(limit), _MAX_PAGE)
    stmt = (
        select(TopologyObservationModel)
        .where(TopologyObservationModel.node_key == node_key)
        .order_by(TopologyObservationModel.observed_at.desc(), TopologyObservationModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def list_observations_for_edge(
    db: Session,
    *,
    edge_key: str,
    limit: int = 20,
) -> list[TopologyObservationModel]:
    limit = min(int(limit), _MAX_PAGE)
    stmt = (
        select(TopologyObservationModel)
        .where(TopologyObservationModel.edge_key == edge_key)
        .order_by(TopologyObservationModel.observed_at.desc(), TopologyObservationModel.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def count_observations_for_node(db: Session, *, node_key: str) -> int:
    return int(
        db.execute(
            select(func.count(TopologyObservationModel.id)).where(TopologyObservationModel.node_key == node_key)
        ).scalar()
        or 0
    )


def count_observations_for_edge(db: Session, *, edge_key: str) -> int:
    return int(
        db.execute(
            select(func.count(TopologyObservationModel.id)).where(TopologyObservationModel.edge_key == edge_key)
        ).scalar()
        or 0
    )


def evidence_sources_for_node(db: Session, *, node_key: str, limit: int = 12) -> list[tuple[str, int, datetime | None]]:
    stmt = (
        select(
            TopologyObservationModel.source_type,
            func.count(TopologyObservationModel.id),
            func.max(TopologyObservationModel.observed_at),
        )
        .where(TopologyObservationModel.node_key == node_key)
        .group_by(TopologyObservationModel.source_type)
        .order_by(func.count(TopologyObservationModel.id).desc(), func.max(TopologyObservationModel.observed_at).desc())
        .limit(min(int(limit), 50))
    )
    return [(str(row[0]), int(row[1] or 0), row[2]) for row in db.execute(stmt).all()]


def evidence_sources_for_edge(db: Session, *, edge_key: str, limit: int = 12) -> list[tuple[str, int, datetime | None]]:
    stmt = (
        select(
            TopologyObservationModel.source_type,
            func.count(TopologyObservationModel.id),
            func.max(TopologyObservationModel.observed_at),
        )
        .where(TopologyObservationModel.edge_key == edge_key)
        .group_by(TopologyObservationModel.source_type)
        .order_by(func.count(TopologyObservationModel.id).desc(), func.max(TopologyObservationModel.observed_at).desc())
        .limit(min(int(limit), 50))
    )
    return [(str(row[0]), int(row[1] or 0), row[2]) for row in db.execute(stmt).all()]


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


def list_subnet_nodes_page(
    db: Session,
    *,
    page_size: int,
    agent_id: str | None,
    since: datetime | None,
    until: datetime | None,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[TopologyNodeModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = (
        select(TopologyNodeModel)
        .where(TopologyNodeModel.node_type == "subnet")
        .order_by(TopologyNodeModel.last_seen_at.desc(), TopologyNodeModel.id.desc())
    )
    if agent_id:
        stmt = stmt.where(TopologyNodeModel.agent_id == agent_id)
    if since is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at >= since)
    if until is not None:
        stmt = stmt.where(TopologyNodeModel.last_seen_at <= until)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                TopologyNodeModel.last_seen_at < c_ts,
                and_(
                    TopologyNodeModel.last_seen_at == c_ts,
                    TopologyNodeModel.id < c_id,
                ),
            )
        )
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


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

    nodes_with_exposure_findings = int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(
                TopologyNodeModel.node_type.not_in(["subnet"]),
                exists(
                    select(TopologyEdgeModel.id).where(
                        TopologyEdgeModel.edge_type == "exposure_related",
                        or_(
                            TopologyEdgeModel.source_node_key == TopologyNodeModel.node_key,
                            TopologyEdgeModel.target_node_key == TopologyNodeModel.node_key,
                        ),
                    )
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
        "nodes_with_exposure_findings": nodes_with_exposure_findings,
        "isolated_nodes": isolated_nodes,
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


def mark_all_nodes_stale(db: Session) -> int:
    result = db.execute(update(TopologyNodeModel).values(is_stale=1))
    return int(result.rowcount or 0)


def count_stale_nodes(db: Session) -> int:
    return int(
        db.execute(
            select(func.count(TopologyNodeModel.id)).where(TopologyNodeModel.is_stale == 1)
        ).scalar()
        or 0
    )
