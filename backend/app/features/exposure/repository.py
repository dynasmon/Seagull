from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import and_, case, exists, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel
from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel
from app.features.exposure.domain.constants import (
    RC_ATTACK_CHAIN_PROGRESSION,
    RC_CRITICAL_CVE,
    RC_PERSISTENCE_SIGNAL,
)
from app.features.exposure.domain.types import EdgeInput, FindingInput, NodeInput, PostureInput
from app.features.exposure.models import (
    ExposureAssetPostureModel,
    ExposureEdgeModel,
    ExposureFindingModel,
    ExposureNodeModel,
    ExposureScoreHistoryModel,
)
from app.features.investigations.models import InvestigationEvidenceBookmarkModel, InvestigationWorkspaceModel
from app.features.inventory.models import AgentInventoryLatestModel, AgentInventorySnapshotModel
from app.features.response.models import ResponseActionModel, ResponseActionResultModel
from app.features.vuln.models import VulnFindingModel


_MAX_PAGE = 200
_MAX_GRAPH_FETCH = 1200
_OPEN_WORKSPACE_STATUSES = ("open", "contained")
_ACTIVE_FINDING_STATUSES = ("open", "acknowledged")


def upsert_asset_posture(db: Session, posture: PostureInput) -> ExposureAssetPostureModel:
    stmt = (
        pg_insert(ExposureAssetPostureModel)
        .values(
            asset_key=posture.asset_key,
            agent_id=posture.agent_id,
            asset_type=posture.asset_type,
            display_name=posture.display_name,
            hostname=posture.hostname,
            environment=posture.environment,
            criticality=posture.criticality,
            severity=posture.severity,
            risk_score=posture.risk_score,
            confidence=posture.confidence,
            exposure_score=posture.breakdown.exposure_score,
            vulnerability_score=posture.breakdown.vulnerability_score,
            active_threat_score=posture.breakdown.active_threat_score,
            persistence_score=posture.breakdown.persistence_score,
            attack_chain_score=posture.breakdown.attack_chain_score,
            asset_criticality_score=posture.breakdown.asset_criticality_score,
            reliability_penalty=posture.breakdown.reliability_penalty,
            status=posture.status,
            first_seen_at=posture.first_seen_at,
            last_seen_at=posture.last_seen_at,
            updated_at=datetime.now(timezone.utc),
            score_breakdown=posture.breakdown.to_dict(),
            reason_codes=posture.reason_codes,
            top_recommendations=[r if isinstance(r, dict) else r for r in posture.top_recommendations],
            evidence_counts=posture.evidence_counts,
            extra_data=posture.extra_data,
        )
        .on_conflict_do_update(
            index_elements=["asset_key"],
            set_={
                "agent_id": posture.agent_id,
                "asset_type": posture.asset_type,
                "display_name": posture.display_name,
                "hostname": posture.hostname,
                "environment": posture.environment,
                "criticality": posture.criticality,
                "severity": posture.severity,
                "risk_score": posture.risk_score,
                "confidence": posture.confidence,
                "exposure_score": posture.breakdown.exposure_score,
                "vulnerability_score": posture.breakdown.vulnerability_score,
                "active_threat_score": posture.breakdown.active_threat_score,
                "persistence_score": posture.breakdown.persistence_score,
                "attack_chain_score": posture.breakdown.attack_chain_score,
                "asset_criticality_score": posture.breakdown.asset_criticality_score,
                "reliability_penalty": posture.breakdown.reliability_penalty,
                "status": posture.status,
                "last_seen_at": posture.last_seen_at,
                "updated_at": datetime.now(timezone.utc),
                "score_breakdown": posture.breakdown.to_dict(),
                "reason_codes": posture.reason_codes,
                "top_recommendations": posture.top_recommendations,
                "evidence_counts": posture.evidence_counts,
                "extra_data": posture.extra_data,
            },
        )
        .returning(ExposureAssetPostureModel)
    )
    return db.execute(stmt).scalars().one()


def get_asset_posture(db: Session, asset_key: str) -> ExposureAssetPostureModel | None:
    stmt = select(ExposureAssetPostureModel).where(ExposureAssetPostureModel.asset_key == asset_key)
    return db.execute(stmt).scalars().first()


def list_assets_page(
    db: Session,
    *,
    page_size: int,
    q: str | None,
    severity: str | None,
    min_score: int | None,
    agent_id: str | None,
    status: str | None,
    reason_code: str | None,
    has_attack_chain: bool | None,
    has_critical_vuln: bool | None,
    has_persistence_signal: bool | None,
    sort: str,
    cursor: dict[str, Any] | None,
) -> list[ExposureAssetPostureModel]:
    page_size = max(1, min(int(page_size), _MAX_PAGE))
    stmt = select(ExposureAssetPostureModel)
    stmt = _apply_posture_filters(
        stmt,
        q=q,
        severity=severity,
        min_score=min_score,
        agent_id=agent_id,
        status=status,
        reason_code=reason_code,
        has_attack_chain=has_attack_chain,
        has_critical_vuln=has_critical_vuln,
        has_persistence_signal=has_persistence_signal,
    )
    stmt = _apply_asset_sort(stmt, sort=sort, cursor=cursor)
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def exposure_summary_metrics(db: Session) -> dict[str, Any]:
    row = db.execute(
        select(
            func.count(ExposureAssetPostureModel.id),
            func.sum(case((ExposureAssetPostureModel.severity == "critical", 1), else_=0)),
            func.sum(case((ExposureAssetPostureModel.severity == "high", 1), else_=0)),
            func.sum(case((ExposureAssetPostureModel.severity == "medium", 1), else_=0)),
            func.sum(case((ExposureAssetPostureModel.severity == "low", 1), else_=0)),
            func.sum(case((ExposureAssetPostureModel.severity == "informational", 1), else_=0)),
            func.avg(ExposureAssetPostureModel.risk_score),
            func.max(ExposureAssetPostureModel.risk_score),
            func.max(ExposureAssetPostureModel.updated_at),
            func.sum(case((ExposureAssetPostureModel.reason_codes.contains(["stale_agent"]), 1), else_=0)),
            func.sum(case((ExposureAssetPostureModel.reason_codes.contains(["stale_inventory"]), 1), else_=0)),
            func.sum(
                case(
                    (
                        or_(
                            ExposureAssetPostureModel.attack_chain_score > 0,
                            ExposureAssetPostureModel.reason_codes.contains([RC_ATTACK_CHAIN_PROGRESSION]),
                        ),
                        1,
                    ),
                    else_=0,
                )
            ),
        )
    ).one()

    active_findings = int(
        db.execute(
            select(func.count(ExposureFindingModel.id)).where(ExposureFindingModel.status.in_(_ACTIVE_FINDING_STATUSES))
        ).scalar()
        or 0
    )
    return {
        "total_assets": int(row[0] or 0),
        "critical_assets": int(row[1] or 0),
        "high_assets": int(row[2] or 0),
        "medium_assets": int(row[3] or 0),
        "low_assets": int(row[4] or 0),
        "informational_assets": int(row[5] or 0),
        "avg_risk_score": float(row[6] or 0.0),
        "max_risk_score": int(row[7] or 0),
        "updated_at": row[8],
        "stale_agents": int(row[9] or 0),
        "stale_inventory_assets": int(row[10] or 0),
        "active_attack_paths": int(row[11] or 0),
        "active_findings": active_findings,
    }


def list_posture_vectors(db: Session) -> list[tuple[list[str], list[dict[str, Any]], int]]:
    rows = db.execute(
        select(
            ExposureAssetPostureModel.reason_codes,
            ExposureAssetPostureModel.top_recommendations,
            ExposureAssetPostureModel.attack_chain_score,
        )
    ).all()
    out: list[tuple[list[str], list[dict[str, Any]], int]] = []
    for reason_codes, recommendations, attack_chain_score in rows:
        out.append(
            (
                list(reason_codes) if isinstance(reason_codes, list) else [],
                list(recommendations) if isinstance(recommendations, list) else [],
                int(attack_chain_score or 0),
            )
        )
    return out


def upsert_node(db: Session, node: NodeInput) -> ExposureNodeModel:
    stmt = (
        pg_insert(ExposureNodeModel)
        .values(
            node_key=node.node_key,
            node_type=node.node_type,
            asset_key=node.asset_key,
            agent_id=node.agent_id,
            label=node.label,
            severity=node.severity,
            risk_score=node.risk_score,
            confidence=node.confidence,
            first_seen_at=node.first_seen_at,
            last_seen_at=node.last_seen_at,
            updated_at=datetime.now(timezone.utc),
            properties=node.properties,
            source_refs=node.source_refs,
        )
        .on_conflict_do_update(
            index_elements=["node_key"],
            set_={
                "label": node.label,
                "severity": node.severity,
                "risk_score": node.risk_score,
                "confidence": node.confidence,
                "last_seen_at": node.last_seen_at,
                "updated_at": datetime.now(timezone.utc),
                "properties": node.properties,
                "source_refs": node.source_refs,
            },
        )
        .returning(ExposureNodeModel)
    )
    return db.execute(stmt).scalars().one()


def get_node(db: Session, node_key: str) -> ExposureNodeModel | None:
    stmt = select(ExposureNodeModel).where(ExposureNodeModel.node_key == node_key)
    return db.execute(stmt).scalars().first()


def list_nodes_for_asset(db: Session, *, asset_key: str, page_size: int = 100) -> list[ExposureNodeModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = (
        select(ExposureNodeModel)
        .where(ExposureNodeModel.asset_key == asset_key)
        .order_by(ExposureNodeModel.risk_score.desc(), ExposureNodeModel.id.desc())
        .limit(page_size)
    )
    return db.execute(stmt).scalars().all()


def list_graph_nodes(
    db: Session,
    *,
    asset_key: str,
    node_types: Sequence[str] | None,
    min_confidence: int,
    limit: int,
) -> list[ExposureNodeModel]:
    stmt = select(ExposureNodeModel).where(
        ExposureNodeModel.asset_key == asset_key,
        ExposureNodeModel.confidence >= int(min_confidence),
    )
    if node_types:
        stmt = stmt.where(ExposureNodeModel.node_type.in_(list(node_types)))
    stmt = stmt.order_by(ExposureNodeModel.risk_score.desc(), ExposureNodeModel.confidence.desc(), ExposureNodeModel.id.desc())
    return db.execute(stmt.limit(min(int(limit), _MAX_GRAPH_FETCH))).scalars().all()


def upsert_edge(db: Session, edge: EdgeInput) -> ExposureEdgeModel:
    stmt = (
        pg_insert(ExposureEdgeModel)
        .values(
            edge_key=edge.edge_key,
            source_node_key=edge.source_node_key,
            target_node_key=edge.target_node_key,
            edge_type=edge.edge_type,
            asset_key=edge.asset_key,
            agent_id=edge.agent_id,
            weight=edge.weight,
            confidence=edge.confidence,
            first_seen_at=edge.first_seen_at,
            last_seen_at=edge.last_seen_at,
            updated_at=datetime.now(timezone.utc),
            properties=edge.properties,
            evidence_refs=edge.evidence_refs,
        )
        .on_conflict_do_update(
            index_elements=["edge_key"],
            set_={
                "weight": edge.weight,
                "confidence": edge.confidence,
                "last_seen_at": edge.last_seen_at,
                "updated_at": datetime.now(timezone.utc),
                "properties": edge.properties,
                "evidence_refs": edge.evidence_refs,
            },
        )
        .returning(ExposureEdgeModel)
    )
    return db.execute(stmt).scalars().one()


def list_edges_for_asset(db: Session, *, asset_key: str, page_size: int = 100) -> list[ExposureEdgeModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = (
        select(ExposureEdgeModel)
        .where(ExposureEdgeModel.asset_key == asset_key)
        .order_by(ExposureEdgeModel.confidence.desc(), ExposureEdgeModel.id.desc())
        .limit(page_size)
    )
    return db.execute(stmt).scalars().all()


def list_graph_edges(
    db: Session,
    *,
    asset_key: str,
    edge_types: Sequence[str] | None,
    min_confidence: int,
    limit: int,
) -> list[ExposureEdgeModel]:
    stmt = select(ExposureEdgeModel).where(
        ExposureEdgeModel.asset_key == asset_key,
        ExposureEdgeModel.confidence >= int(min_confidence),
    )
    if edge_types:
        stmt = stmt.where(ExposureEdgeModel.edge_type.in_(list(edge_types)))
    stmt = stmt.order_by(ExposureEdgeModel.confidence.desc(), ExposureEdgeModel.weight.desc(), ExposureEdgeModel.id.desc())
    return db.execute(stmt.limit(min(int(limit), _MAX_GRAPH_FETCH))).scalars().all()


def upsert_finding(db: Session, finding: FindingInput) -> ExposureFindingModel:
    stmt = (
        pg_insert(ExposureFindingModel)
        .values(
            finding_key=finding.finding_key,
            asset_key=finding.asset_key,
            agent_id=finding.agent_id,
            finding_type=finding.finding_type,
            severity=finding.severity,
            score_delta=finding.score_delta,
            confidence=finding.confidence,
            title=finding.title,
            summary=finding.summary,
            status=finding.status,
            first_seen_at=finding.first_seen_at,
            last_seen_at=finding.last_seen_at,
            updated_at=datetime.now(timezone.utc),
            related_node_keys=finding.related_node_keys,
            evidence_refs=[r.to_dict() for r in finding.evidence_refs],
            reason_codes=finding.reason_codes,
            recommendations=finding.recommendations,
            extra_data=finding.extra_data,
        )
        .on_conflict_do_update(
            index_elements=["finding_key"],
            set_={
                "severity": finding.severity,
                "score_delta": finding.score_delta,
                "confidence": finding.confidence,
                "title": finding.title,
                "summary": finding.summary,
                "status": finding.status,
                "last_seen_at": finding.last_seen_at,
                "updated_at": datetime.now(timezone.utc),
                "related_node_keys": finding.related_node_keys,
                "evidence_refs": [r.to_dict() for r in finding.evidence_refs],
                "reason_codes": finding.reason_codes,
                "recommendations": finding.recommendations,
                "extra_data": finding.extra_data,
            },
        )
        .returning(ExposureFindingModel)
    )
    return db.execute(stmt).scalars().one()


def get_finding(db: Session, finding_key: str) -> ExposureFindingModel | None:
    stmt = select(ExposureFindingModel).where(ExposureFindingModel.finding_key == finding_key)
    return db.execute(stmt).scalars().first()


def list_findings_page(
    db: Session,
    *,
    page_size: int,
    asset_key: str | None = None,
    agent_id: str | None = None,
    finding_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    q: str | None = None,
    cursor_parsed: tuple[datetime, int] | None = None,
) -> list[ExposureFindingModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = select(ExposureFindingModel).order_by(
        ExposureFindingModel.last_seen_at.desc(),
        ExposureFindingModel.id.desc(),
    )
    if asset_key:
        stmt = stmt.where(ExposureFindingModel.asset_key == asset_key)
    if agent_id:
        stmt = stmt.where(ExposureFindingModel.agent_id == agent_id)
    if finding_type:
        stmt = stmt.where(ExposureFindingModel.finding_type == finding_type)
    if severity:
        stmt = stmt.where(ExposureFindingModel.severity == severity)
    if status:
        stmt = stmt.where(ExposureFindingModel.status == status)
    if q:
        token = f"%{q}%"
        stmt = stmt.where(
            or_(
                ExposureFindingModel.finding_key.ilike(token),
                ExposureFindingModel.title.ilike(token),
                ExposureFindingModel.summary.ilike(token),
            )
        )
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                ExposureFindingModel.last_seen_at < c_ts,
                and_(
                    ExposureFindingModel.last_seen_at == c_ts,
                    ExposureFindingModel.id < c_id,
                ),
            )
        )
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def list_findings_for_asset(
    db: Session,
    *,
    asset_key: str,
    limit: int,
    active_only: bool = False,
) -> list[ExposureFindingModel]:
    stmt = select(ExposureFindingModel).where(ExposureFindingModel.asset_key == asset_key)
    if active_only:
        stmt = stmt.where(ExposureFindingModel.status.in_(_ACTIVE_FINDING_STATUSES))
    stmt = stmt.order_by(
        ExposureFindingModel.score_delta.desc(),
        ExposureFindingModel.confidence.desc(),
        ExposureFindingModel.last_seen_at.desc(),
        ExposureFindingModel.id.desc(),
    )
    return db.execute(stmt.limit(max(1, int(limit)))).scalars().all()


def insert_score_history(
    db: Session,
    *,
    asset_key: str,
    agent_id: str | None,
    bucket_ts: datetime,
    risk_score: int,
    severity: str,
    confidence: int,
    score_breakdown: dict[str, Any],
) -> ExposureScoreHistoryModel:
    row = ExposureScoreHistoryModel(
        asset_key=asset_key,
        agent_id=agent_id,
        bucket_ts=bucket_ts,
        risk_score=risk_score,
        severity=severity,
        confidence=confidence,
        score_breakdown=score_breakdown,
    )
    db.add(row)
    return row


def list_score_history(
    db: Session,
    *,
    asset_key: str,
    since: datetime | None = None,
    limit: int = 90,
) -> list[ExposureScoreHistoryModel]:
    limit = min(int(limit), 365)
    stmt = (
        select(ExposureScoreHistoryModel)
        .where(ExposureScoreHistoryModel.asset_key == asset_key)
        .order_by(ExposureScoreHistoryModel.bucket_ts.desc())
        .limit(limit)
    )
    if since is not None:
        stmt = stmt.where(ExposureScoreHistoryModel.bucket_ts >= since)
    return db.execute(stmt).scalars().all()


def get_inventory_context(db: Session, *, agent_id: str) -> dict[str, Any]:
    latest_row = db.execute(
        select(
            AgentInventoryLatestModel.snapshot_id,
            AgentInventoryLatestModel.os,
            AgentInventoryLatestModel.collected_at,
            AgentInventoryLatestModel.updated_at,
        ).where(AgentInventoryLatestModel.agent_id == agent_id)
    ).mappings().first()
    if not latest_row:
        return {}

    os_data = latest_row.get("os") if isinstance(latest_row.get("os"), dict) else {}
    hostname = str(os_data.get("hostname") or os_data.get("fqdn") or "").strip() or None
    ip_addresses: list[str] = []
    raw_addresses = os_data.get("addresses") or os_data.get("ip_addresses") or []
    if isinstance(raw_addresses, list):
        for raw in raw_addresses[:32]:
            value = str(raw or "").strip()
            if value:
                ip_addresses.append(value)
    interfaces = os_data.get("interfaces") or []
    if isinstance(interfaces, list):
        for iface in interfaces[:16]:
            if not isinstance(iface, dict):
                continue
            for key in ("ip", "ip_address", "address"):
                value = str(iface.get(key) or "").strip()
                if value and value not in ip_addresses:
                    ip_addresses.append(value)

    packages_count = 0
    snapshot_id = latest_row.get("snapshot_id")
    if snapshot_id is not None:
        snap_row = db.execute(
            select(AgentInventorySnapshotModel.packages_count).where(AgentInventorySnapshotModel.id == int(snapshot_id))
        ).first()
        if snap_row:
            packages_count = int(snap_row[0] or 0)

    return {
        "hostname": hostname,
        "ip_addresses": ip_addresses,
        "collected_at": latest_row.get("collected_at"),
        "updated_at": latest_row.get("updated_at"),
        "packages_count": packages_count,
    }


def list_attack_chain_cases_for_agent(
    db: Session,
    *,
    agent_id: str,
    open_only: bool,
    limit: int,
) -> list[AttackChainCaseModel]:
    stmt = select(AttackChainCaseModel).where(AttackChainCaseModel.agent_id == agent_id)
    if open_only:
        stmt = stmt.where(AttackChainCaseModel.status == "open")
    stmt = stmt.order_by(AttackChainCaseModel.score.desc(), AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
    return db.execute(stmt.limit(max(1, int(limit)))).scalars().all()


def list_attack_chain_steps_for_cases(
    db: Session,
    *,
    case_ids: Iterable[int],
    limit: int,
) -> list[AttackChainStepModel]:
    ids = [int(value) for value in case_ids if int(value) > 0]
    if not ids:
        return []
    stmt = (
        select(AttackChainStepModel)
        .where(AttackChainStepModel.case_id.in_(ids))
        .order_by(AttackChainStepModel.timestamp.desc(), AttackChainStepModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return db.execute(stmt).scalars().all()


def list_vulnerabilities_for_asset(
    db: Session,
    *,
    asset_key: str,
    limit: int,
    active_only: bool,
) -> list[VulnFindingModel]:
    stmt = select(VulnFindingModel).where(VulnFindingModel.asset_key == asset_key)
    if active_only:
        stmt = stmt.where(
            VulnFindingModel.is_suppressed.is_(False),
            VulnFindingModel.observation_state == "observed",
            VulnFindingModel.operator_disposition == "open",
        )
    stmt = stmt.order_by(VulnFindingModel.severity_rank.desc(), VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc())
    return db.execute(stmt.limit(max(1, int(limit)))).scalars().all()


def list_alerts_for_asset(
    db: Session,
    *,
    agent_id: str | None,
    asset_ips: Sequence[str],
    hostname: str | None,
    limit: int,
    since: datetime | None = None,
) -> list[AlertModel]:
    conditions = []
    if agent_id:
        conditions.append(func.jsonb_extract_path_text(AlertModel.details, "agent_id") == agent_id)
    ips = [str(value or "").strip() for value in asset_ips if str(value or "").strip()]
    if ips:
        conditions.append(AlertModel.src_ip.in_(ips))
        conditions.append(AlertModel.dst_ip.in_(ips))
    if hostname:
        conditions.append(func.lower(func.jsonb_extract_path_text(AlertModel.details, "hostname")) == hostname.lower())
    if not conditions:
        return []

    stmt = select(AlertModel).where(or_(*conditions))
    if since is not None:
        stmt = stmt.where(AlertModel.created_at >= since)
    stmt = stmt.order_by(AlertModel.created_at.desc(), AlertModel.id.desc()).limit(max(1, int(limit)))
    return db.execute(stmt).scalars().all()


def list_investigations_for_asset(
    db: Session,
    *,
    asset_key: str,
    agent_id: str | None,
    limit: int,
) -> list[InvestigationWorkspaceModel]:
    bookmark_exists = exists(
        select(InvestigationEvidenceBookmarkModel.id).where(
            InvestigationEvidenceBookmarkModel.workspace_id == InvestigationWorkspaceModel.id,
            InvestigationEvidenceBookmarkModel.metadata_json["asset_key"].astext == asset_key,
        )
    )
    conditions = [bookmark_exists, InvestigationWorkspaceModel.summary["exposure_asset_key"].astext == asset_key]
    if agent_id:
        conditions.append(InvestigationWorkspaceModel.primary_agent_id == agent_id)
        conditions.append(
            exists(
                select(InvestigationEvidenceBookmarkModel.id).where(
                    InvestigationEvidenceBookmarkModel.workspace_id == InvestigationWorkspaceModel.id,
                    InvestigationEvidenceBookmarkModel.agent_id == agent_id,
                )
            )
        )
    stmt = (
        select(InvestigationWorkspaceModel)
        .where(or_(*conditions))
        .order_by(InvestigationWorkspaceModel.updated_at.desc(), InvestigationWorkspaceModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return db.execute(stmt).scalars().all()


def list_open_workspaces_for_context(
    db: Session,
    *,
    asset_key: str,
    agent_id: str | None,
    linked_attack_chain_case_id: int | None,
    limit: int,
) -> list[InvestigationWorkspaceModel]:
    conditions = [InvestigationWorkspaceModel.summary["exposure_asset_key"].astext == asset_key]
    if agent_id:
        conditions.append(InvestigationWorkspaceModel.primary_agent_id == agent_id)
    if linked_attack_chain_case_id is not None:
        conditions.append(InvestigationWorkspaceModel.linked_attack_chain_case_id == int(linked_attack_chain_case_id))
    stmt = (
        select(InvestigationWorkspaceModel)
        .where(
            InvestigationWorkspaceModel.status.in_(_OPEN_WORKSPACE_STATUSES),
            or_(*conditions),
        )
        .order_by(InvestigationWorkspaceModel.updated_at.desc(), InvestigationWorkspaceModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return db.execute(stmt).scalars().all()


def list_response_actions_for_agent(
    db: Session,
    *,
    agent_id: str,
    limit: int,
) -> list[ResponseActionModel]:
    stmt = (
        select(ResponseActionModel)
        .where(ResponseActionModel.agent_id == agent_id)
        .order_by(ResponseActionModel.requested_at.desc(), ResponseActionModel.id.desc())
        .limit(max(1, int(limit)))
    )
    return db.execute(stmt).scalars().all()


def latest_response_results_for_actions(
    db: Session,
    *,
    action_ids: Iterable[int],
) -> dict[int, ResponseActionResultModel]:
    ids = [int(value) for value in action_ids if int(value) > 0]
    if not ids:
        return {}
    latest_rows = db.execute(
        select(
            ResponseActionResultModel.response_action_id,
            func.max(ResponseActionResultModel.id).label("latest_id"),
        )
        .where(ResponseActionResultModel.response_action_id.in_(ids))
        .group_by(ResponseActionResultModel.response_action_id)
    ).all()
    latest_ids = [int(row[1]) for row in latest_rows if row[1] is not None]
    if not latest_ids:
        return {}
    rows = db.execute(select(ResponseActionResultModel).where(ResponseActionResultModel.id.in_(latest_ids))).scalars().all()
    by_id = {int(row.id): row for row in rows}
    out: dict[int, ResponseActionResultModel] = {}
    for action_id, latest_id in latest_rows:
        if latest_id is None:
            continue
        row = by_id.get(int(latest_id))
        if row is not None:
            out[int(action_id)] = row
    return out


def _apply_posture_filters(
    stmt,
    *,
    q: str | None,
    severity: str | None,
    min_score: int | None,
    agent_id: str | None,
    status: str | None,
    reason_code: str | None,
    has_attack_chain: bool | None,
    has_critical_vuln: bool | None,
    has_persistence_signal: bool | None,
):
    if q:
        token = f"%{q}%"
        stmt = stmt.where(
            or_(
                ExposureAssetPostureModel.asset_key.ilike(token),
                ExposureAssetPostureModel.agent_id.ilike(token),
                ExposureAssetPostureModel.display_name.ilike(token),
                ExposureAssetPostureModel.hostname.ilike(token),
            )
        )
    if severity:
        stmt = stmt.where(ExposureAssetPostureModel.severity == severity)
    if min_score is not None:
        stmt = stmt.where(ExposureAssetPostureModel.risk_score >= int(min_score))
    if agent_id:
        stmt = stmt.where(ExposureAssetPostureModel.agent_id == agent_id)
    if status:
        stmt = stmt.where(ExposureAssetPostureModel.status == status)
    if reason_code:
        stmt = stmt.where(ExposureAssetPostureModel.reason_codes.contains([reason_code]))
    if has_attack_chain is not None:
        cond = or_(
            ExposureAssetPostureModel.attack_chain_score > 0,
            ExposureAssetPostureModel.reason_codes.contains([RC_ATTACK_CHAIN_PROGRESSION]),
        )
        stmt = stmt.where(cond if has_attack_chain else ~cond)
    if has_critical_vuln is not None:
        cond = or_(
            ExposureAssetPostureModel.reason_codes.contains([RC_CRITICAL_CVE]),
            ExposureAssetPostureModel.vulnerability_score >= 20,
        )
        stmt = stmt.where(cond if has_critical_vuln else ~cond)
    if has_persistence_signal is not None:
        cond = or_(
            ExposureAssetPostureModel.reason_codes.contains([RC_PERSISTENCE_SIGNAL]),
            ExposureAssetPostureModel.persistence_score > 0,
        )
        stmt = stmt.where(cond if has_persistence_signal else ~cond)
    return stmt


def _apply_asset_sort(stmt, *, sort: str, cursor: dict[str, Any] | None):
    normalized = str(sort or "risk_desc").strip().lower()
    if normalized == "risk_asc":
        if cursor:
            stmt = stmt.where(
                or_(
                    ExposureAssetPostureModel.risk_score > int(cursor.get("risk_score") or 0),
                    and_(
                        ExposureAssetPostureModel.risk_score == int(cursor.get("risk_score") or 0),
                        ExposureAssetPostureModel.id < int(cursor.get("id") or 0),
                    ),
                )
            )
        return stmt.order_by(ExposureAssetPostureModel.risk_score.asc(), ExposureAssetPostureModel.id.desc())
    if normalized == "updated_desc":
        if cursor:
            cursor_ts = cursor.get("updated_at")
            stmt = stmt.where(
                or_(
                    ExposureAssetPostureModel.updated_at < cursor_ts,
                    and_(
                        ExposureAssetPostureModel.updated_at == cursor_ts,
                        ExposureAssetPostureModel.id < int(cursor.get("id") or 0),
                    ),
                )
            )
        return stmt.order_by(ExposureAssetPostureModel.updated_at.desc(), ExposureAssetPostureModel.id.desc())
    if normalized == "last_seen_desc":
        if cursor:
            cursor_ts = cursor.get("last_seen_at")
            stmt = stmt.where(
                or_(
                    ExposureAssetPostureModel.last_seen_at < cursor_ts,
                    and_(
                        ExposureAssetPostureModel.last_seen_at == cursor_ts,
                        ExposureAssetPostureModel.id < int(cursor.get("id") or 0),
                    ),
                )
            )
        return stmt.order_by(ExposureAssetPostureModel.last_seen_at.desc(), ExposureAssetPostureModel.id.desc())
    if cursor:
        stmt = stmt.where(
            or_(
                ExposureAssetPostureModel.risk_score < int(cursor.get("risk_score") or 0),
                and_(
                    ExposureAssetPostureModel.risk_score == int(cursor.get("risk_score") or 0),
                    ExposureAssetPostureModel.id < int(cursor.get("id") or 0),
                ),
            )
        )
    return stmt.order_by(ExposureAssetPostureModel.risk_score.desc(), ExposureAssetPostureModel.id.desc())
