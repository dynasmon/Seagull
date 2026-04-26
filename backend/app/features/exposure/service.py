from __future__ import annotations

import base64
import struct
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.features.exposure import repository
from app.features.exposure.domain.evidence import (
    count_evidence_by_source,
    derive_aggregate_confidence,
    evidence_refs_to_list,
)
from app.features.exposure.domain.normalization import (
    normalize_asset_status,
    normalize_finding_status,
    normalize_finding_type,
    normalize_severity,
    severity_from_score,
)
from app.features.exposure.domain.recommendations import generate_recommendations
from app.features.exposure.domain.scoring import ScoringInputs, compute_risk_score
from app.features.exposure.domain.types import (
    EdgeInput,
    EvidenceRef,
    FindingInput,
    NodeInput,
    PostureInput,
)
from app.features.exposure.models import (
    ExposureAssetPostureModel,
    ExposureEdgeModel,
    ExposureFindingModel,
    ExposureNodeModel,
    ExposureScoreHistoryModel,
)
from app.shared.schemas import CursorPage


def _parse_cursor_ts_id(cursor: str) -> tuple[datetime, int] | None:
    try:
        data = base64.urlsafe_b64decode(cursor + "==")
        ts_int, row_id = struct.unpack(">QI", data[:12])
        ts = datetime.fromtimestamp(ts_int / 1_000_000, tz=timezone.utc)
        return ts, row_id
    except Exception:
        return None


def _make_cursor_ts_id(ts: datetime, row_id: int) -> str:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ts_int = int(ts.timestamp() * 1_000_000)
    data = struct.pack(">QI", ts_int, row_id)
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def compute_and_upsert_posture(
    db: Session,
    *,
    asset_key: str,
    agent_id: str | None,
    asset_type: str,
    display_name: str,
    hostname: str | None,
    environment: str | None,
    criticality: str,
    scoring_inputs: ScoringInputs,
    first_seen_at: datetime,
    last_seen_at: datetime,
    evidence_refs: list[EvidenceRef] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ExposureAssetPostureModel:
    refs = evidence_refs or []
    scoring_inputs.evidence_refs = refs
    scoring_inputs.base_confidence = derive_aggregate_confidence(refs, base_confidence=scoring_inputs.base_confidence)

    risk_score, breakdown, confidence, reason_codes = compute_risk_score(scoring_inputs)
    severity = severity_from_score(risk_score)
    recommendations = generate_recommendations(reason_codes, evidence_refs=evidence_refs_to_list(refs))
    status = normalize_asset_status(None)
    if last_seen_at:
        from app.features.exposure.domain.normalization import asset_status_from_age  # noqa: PLC0415
        status = asset_status_from_age(last_seen_at)

    posture = PostureInput(
        asset_key=asset_key,
        agent_id=agent_id,
        asset_type=asset_type,
        display_name=display_name,
        hostname=hostname,
        environment=environment,
        criticality=criticality,
        risk_score=risk_score,
        severity=severity,
        confidence=confidence,
        breakdown=breakdown,
        status=status,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        reason_codes=reason_codes,
        top_recommendations=[r.to_dict() for r in recommendations],
        evidence_counts=count_evidence_by_source(refs),
        extra_data=metadata or {},
    )
    return repository.upsert_asset_posture(db, posture)


def record_score_history(
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
    return repository.insert_score_history(
        db,
        asset_key=asset_key,
        agent_id=agent_id,
        bucket_ts=bucket_ts,
        risk_score=risk_score,
        severity=severity,
        confidence=confidence,
        score_breakdown=score_breakdown,
    )


def upsert_node(db: Session, node: NodeInput) -> ExposureNodeModel:
    return repository.upsert_node(db, node)


def upsert_edge(db: Session, edge: EdgeInput) -> ExposureEdgeModel:
    return repository.upsert_edge(db, edge)


def upsert_finding(db: Session, finding: FindingInput) -> ExposureFindingModel:
    return repository.upsert_finding(db, finding)


def list_asset_postures(
    db: Session,
    *,
    agent_id: str | None = None,
    min_score: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    page_size: int = 50,
    cursor: str | None = None,
) -> CursorPage[ExposureAssetPostureModel]:
    cursor_parsed = _parse_cursor_ts_id(cursor) if cursor else None
    rows = repository.list_asset_postures_page(
        db,
        page_size=page_size,
        agent_id=agent_id,
        min_score=min_score,
        severity=severity,
        status=status,
        cursor_parsed=cursor_parsed,
    )
    has_more = len(rows) > page_size
    items = rows[:page_size]
    next_cursor = _make_cursor_ts_id(items[-1].last_seen_at, items[-1].id) if has_more and items else None
    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def get_asset_posture(db: Session, asset_key: str) -> ExposureAssetPostureModel | None:
    return repository.get_asset_posture(db, asset_key)


def list_findings(
    db: Session,
    *,
    asset_key: str | None = None,
    agent_id: str | None = None,
    finding_type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    page_size: int = 50,
    cursor: str | None = None,
) -> CursorPage[ExposureFindingModel]:
    cursor_parsed = _parse_cursor_ts_id(cursor) if cursor else None
    rows = repository.list_findings_page(
        db,
        page_size=page_size,
        asset_key=asset_key,
        agent_id=agent_id,
        finding_type=finding_type,
        severity=severity,
        status=status,
        cursor_parsed=cursor_parsed,
    )
    has_more = len(rows) > page_size
    items = rows[:page_size]
    next_cursor = _make_cursor_ts_id(items[-1].last_seen_at, items[-1].id) if has_more and items else None
    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def list_nodes_for_asset(db: Session, *, asset_key: str, page_size: int = 100) -> list[ExposureNodeModel]:
    return repository.list_nodes_for_asset(db, asset_key=asset_key, page_size=page_size)


def list_edges_for_asset(db: Session, *, asset_key: str, page_size: int = 100) -> list[ExposureEdgeModel]:
    return repository.list_edges_for_asset(db, asset_key=asset_key, page_size=page_size)


def list_score_history(
    db: Session,
    *,
    asset_key: str,
    since: datetime | None = None,
    limit: int = 90,
) -> list[ExposureScoreHistoryModel]:
    return repository.list_score_history(db, asset_key=asset_key, since=since, limit=limit)
