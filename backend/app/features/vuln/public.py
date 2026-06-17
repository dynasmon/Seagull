from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.vuln.models import VulnFindingModel


class VulnFindingDTO(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    scan_id: int | None
    asset_key: str
    asset_agent_id: str | None
    reporter_agent_id: str | None
    target: str | None
    asset: dict[str, Any]
    source: str
    external_id: str | None
    fingerprint: str
    severity: str
    severity_rank: int
    confidence: int
    title: str
    description: str | None
    remediation: str | None
    cve: str | None
    cwe: str | None
    cvss: str | None
    location: str | None
    tags: list[Any]
    evidence: dict[str, Any]
    status: str
    is_suppressed: bool
    observation_state: str
    operator_disposition: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrences: int
    updated_at: datetime


class VulnSignalSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    severity: str
    severity_rank: int
    cve: str | None
    cvss: str | None
    title: str
    last_seen_at: datetime
    evidence: dict[str, Any]


class VulnCveSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve: str | None
    severity: str
    severity_rank: int
    cvss: str | None
    location: str | None
    last_seen_at: datetime
    confidence: int


class VulnFindingSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    fingerprint: str
    cve: str | None
    title: str
    severity: str
    severity_rank: int
    confidence: int
    first_seen_at: datetime
    last_seen_at: datetime
    description: str | None


def _to_finding_dto(row: VulnFindingModel) -> VulnFindingDTO:
    return VulnFindingDTO(
        id=row.id,
        scan_id=row.scan_id,
        asset_key=row.asset_key,
        asset_agent_id=row.asset_agent_id,
        reporter_agent_id=row.reporter_agent_id,
        target=row.target,
        asset=row.asset or {},
        source=row.source,
        external_id=row.external_id,
        fingerprint=row.fingerprint,
        severity=row.severity,
        severity_rank=row.severity_rank,
        confidence=row.confidence,
        title=row.title,
        description=row.description,
        remediation=row.remediation,
        cve=row.cve,
        cwe=row.cwe,
        cvss=row.cvss,
        location=row.location,
        tags=row.tags or [],
        evidence=row.evidence or {},
        status=row.status,
        is_suppressed=row.is_suppressed,
        observation_state=row.observation_state,
        operator_disposition=row.operator_disposition,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        occurrences=row.occurrences,
        updated_at=row.updated_at,
    )


def list_recent_findings(db: Session, *, min_ts: datetime, limit: int) -> list[VulnFindingDTO]:
    stmt = (
        select(VulnFindingModel)
        .where(VulnFindingModel.last_seen_at >= min_ts)
        .order_by(VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc())
        .limit(limit)
    )
    return [_to_finding_dto(row) for row in db.execute(stmt).scalars().all()]


def list_findings_for_asset(
    db: Session,
    *,
    asset_key: str,
    limit: int,
    active_only: bool,
) -> list[VulnFindingDTO]:
    stmt = select(VulnFindingModel).where(VulnFindingModel.asset_key == asset_key)
    if active_only:
        stmt = stmt.where(
            VulnFindingModel.is_suppressed.is_(False),
            VulnFindingModel.observation_state == "observed",
            VulnFindingModel.operator_disposition == "open",
        )
    stmt = stmt.order_by(
        VulnFindingModel.severity_rank.desc(),
        VulnFindingModel.last_seen_at.desc(),
        VulnFindingModel.id.desc(),
    )
    rows = db.execute(stmt.limit(max(1, int(limit)))).scalars().all()
    return [_to_finding_dto(row) for row in rows]


def list_active_finding_signals_for_asset(
    db: Session,
    *,
    asset_key: str,
    lookback: datetime,
    limit: int,
) -> list[VulnSignalSummary]:
    stmt = (
        select(
            VulnFindingModel.id,
            VulnFindingModel.severity,
            VulnFindingModel.severity_rank,
            VulnFindingModel.cve,
            VulnFindingModel.cvss,
            VulnFindingModel.title,
            VulnFindingModel.last_seen_at,
            VulnFindingModel.evidence,
        )
        .where(
            VulnFindingModel.asset_key == asset_key,
            VulnFindingModel.is_suppressed.is_(False),
            VulnFindingModel.observation_state == "observed",
            VulnFindingModel.operator_disposition == "open",
            VulnFindingModel.last_seen_at >= lookback,
        )
        .order_by(VulnFindingModel.severity_rank.desc(), VulnFindingModel.id.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).mappings().all()
    return [
        VulnSignalSummary(
            id=r["id"],
            severity=r["severity"],
            severity_rank=r["severity_rank"],
            cve=r["cve"],
            cvss=r["cvss"],
            title=r["title"],
            last_seen_at=r["last_seen_at"],
            evidence=r["evidence"] or {},
        )
        for r in rows
    ]


def list_active_cve_findings_for_asset(
    db: Session,
    *,
    asset_key: str,
    lookback: datetime,
    limit: int,
) -> list[VulnCveSummary]:
    stmt = (
        select(
            VulnFindingModel.cve,
            VulnFindingModel.severity,
            VulnFindingModel.severity_rank,
            VulnFindingModel.cvss,
            VulnFindingModel.location,
            VulnFindingModel.last_seen_at,
            VulnFindingModel.confidence,
        )
        .where(
            VulnFindingModel.asset_key == asset_key,
            VulnFindingModel.cve.isnot(None),
            VulnFindingModel.is_suppressed.is_(False),
            VulnFindingModel.observation_state == "observed",
            VulnFindingModel.last_seen_at >= lookback,
        )
        .order_by(VulnFindingModel.severity_rank.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).mappings().all()
    return [
        VulnCveSummary(
            cve=r["cve"],
            severity=r["severity"],
            severity_rank=r["severity_rank"],
            cvss=r["cvss"],
            location=r["location"],
            last_seen_at=r["last_seen_at"],
            confidence=r["confidence"],
        )
        for r in rows
    ]


def list_open_findings_for_asset(
    db: Session,
    *,
    asset_key: str,
    lookback: datetime,
    limit: int,
) -> list[VulnFindingSummary]:
    stmt = (
        select(
            VulnFindingModel.id,
            VulnFindingModel.fingerprint,
            VulnFindingModel.cve,
            VulnFindingModel.title,
            VulnFindingModel.severity,
            VulnFindingModel.severity_rank,
            VulnFindingModel.confidence,
            VulnFindingModel.first_seen_at,
            VulnFindingModel.last_seen_at,
            VulnFindingModel.description,
        )
        .where(
            VulnFindingModel.asset_key == asset_key,
            VulnFindingModel.is_suppressed.is_(False),
            VulnFindingModel.observation_state == "observed",
            VulnFindingModel.operator_disposition == "open",
            VulnFindingModel.last_seen_at >= lookback,
        )
        .order_by(VulnFindingModel.severity_rank.desc(), VulnFindingModel.id.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).mappings().all()
    return [
        VulnFindingSummary(
            id=r["id"],
            fingerprint=r["fingerprint"],
            cve=r["cve"],
            title=r["title"],
            severity=r["severity"],
            severity_rank=r["severity_rank"],
            confidence=r["confidence"],
            first_seen_at=r["first_seen_at"],
            last_seen_at=r["last_seen_at"],
            description=r["description"],
        )
        for r in rows
    ]


def list_finding_locations_for_asset(
    db: Session,
    *,
    asset_key: str,
    lookback: datetime,
    limit: int,
) -> list[str | None]:
    stmt = (
        select(VulnFindingModel.location)
        .where(
            VulnFindingModel.asset_key == asset_key,
            VulnFindingModel.is_suppressed.is_(False),
            VulnFindingModel.last_seen_at >= lookback,
        )
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())
