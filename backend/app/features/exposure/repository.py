from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.features.exposure.models import (
    ExposureAssetPostureModel,
    ExposureEdgeModel,
    ExposureFindingModel,
    ExposureNodeModel,
    ExposureScoreHistoryModel,
)
from app.features.exposure.domain.types import EdgeInput, FindingInput, NodeInput, PostureInput


_MAX_PAGE = 200


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
            updated_at=datetime.utcnow(),
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
                "updated_at": datetime.utcnow(),
                "score_breakdown": posture.breakdown.to_dict(),
                "reason_codes": posture.reason_codes,
                "top_recommendations": posture.top_recommendations,
                "evidence_counts": posture.evidence_counts,
                "extra_data": posture.extra_data,
            },
        )
        .returning(ExposureAssetPostureModel)
    )
    result = db.execute(stmt)
    return result.scalars().one()


def get_asset_posture(db: Session, asset_key: str) -> ExposureAssetPostureModel | None:
    stmt = select(ExposureAssetPostureModel).where(ExposureAssetPostureModel.asset_key == asset_key)
    return db.execute(stmt).scalars().first()


def list_asset_postures_page(
    db: Session,
    *,
    page_size: int,
    agent_id: str | None = None,
    min_score: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    cursor_parsed: tuple[datetime, int] | None = None,
) -> list[ExposureAssetPostureModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = select(ExposureAssetPostureModel).order_by(
        ExposureAssetPostureModel.last_seen_at.desc(),
        ExposureAssetPostureModel.id.desc(),
    )
    if agent_id:
        stmt = stmt.where(ExposureAssetPostureModel.agent_id == agent_id)
    if min_score is not None:
        stmt = stmt.where(ExposureAssetPostureModel.risk_score >= int(min_score))
    if severity:
        stmt = stmt.where(ExposureAssetPostureModel.severity == severity)
    if status:
        stmt = stmt.where(ExposureAssetPostureModel.status == status)
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                ExposureAssetPostureModel.last_seen_at < c_ts,
                and_(
                    ExposureAssetPostureModel.last_seen_at == c_ts,
                    ExposureAssetPostureModel.id < c_id,
                ),
            )
        )
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


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
            updated_at=datetime.utcnow(),
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
                "updated_at": datetime.utcnow(),
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


def list_nodes_for_asset(
    db: Session,
    *,
    asset_key: str,
    page_size: int = 100,
) -> list[ExposureNodeModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = (
        select(ExposureNodeModel)
        .where(ExposureNodeModel.asset_key == asset_key)
        .order_by(ExposureNodeModel.risk_score.desc(), ExposureNodeModel.id.desc())
        .limit(page_size)
    )
    return db.execute(stmt).scalars().all()


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
            updated_at=datetime.utcnow(),
            properties=edge.properties,
            evidence_refs=edge.evidence_refs,
        )
        .on_conflict_do_update(
            index_elements=["edge_key"],
            set_={
                "weight": edge.weight,
                "confidence": edge.confidence,
                "last_seen_at": edge.last_seen_at,
                "updated_at": datetime.utcnow(),
                "properties": edge.properties,
                "evidence_refs": edge.evidence_refs,
            },
        )
        .returning(ExposureEdgeModel)
    )
    return db.execute(stmt).scalars().one()


def list_edges_for_asset(
    db: Session,
    *,
    asset_key: str,
    page_size: int = 100,
) -> list[ExposureEdgeModel]:
    page_size = min(int(page_size), _MAX_PAGE)
    stmt = (
        select(ExposureEdgeModel)
        .where(ExposureEdgeModel.asset_key == asset_key)
        .order_by(ExposureEdgeModel.confidence.desc(), ExposureEdgeModel.id.desc())
        .limit(page_size)
    )
    return db.execute(stmt).scalars().all()


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
            updated_at=datetime.utcnow(),
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
                "updated_at": datetime.utcnow(),
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


def list_findings_page(
    db: Session,
    *,
    page_size: int,
    asset_key: str | None = None,
    agent_id: str | None = None,
    finding_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
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


def flush(db: Session) -> None:
    db.flush()


def commit(db: Session) -> None:
    db.commit()
