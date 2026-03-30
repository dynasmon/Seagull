from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import Float, and_, case, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.features.agents.models import AgentModel
from app.features.vuln.models import VulnFindingModel, VulnScanModel


def _cvss_numeric_expr(vf=VulnFindingModel):
    return case(
        (vf.cvss.op("~")(r"^[0-9]+(\.[0-9]+)?$"), cast(vf.cvss, Float)),
        else_=0.0,
    )


def _has_fix_expr(vf=VulnFindingModel):
    return or_(
        vf.evidence["osv"]["fixed"].astext.is_not(None),
        and_(vf.remediation.is_not(None), func.btrim(vf.remediation) != ""),
    )


def _internet_exposed_expr(vf=VulnFindingModel):
    return func.upper(func.coalesce(vf.cvss, "")).like("%AV:N%")


def _risk_score_expr(now: datetime, vf=VulnFindingModel):
    cvss_num = _cvss_numeric_expr(vf)
    cve_present = and_(vf.cve.is_not(None), func.btrim(vf.cve) != "")
    has_fix = _has_fix_expr(vf)
    internet_exposed = _internet_exposed_expr(vf)

    cvss_points = case(
        (cvss_num >= 9.0, 16.0),
        (cvss_num >= 7.0, 10.0),
        (cvss_num >= 4.0, 5.0),
        else_=0.0,
    )

    recency_points = case(
        (vf.last_seen_at >= now - timedelta(hours=24), 8.0),
        (vf.last_seen_at >= now - timedelta(days=7), 4.0),
        else_=0.0,
    )

    return func.least(
        100.0,
        (
            cast(vf.severity_rank, Float) * 18.0
            + cast(func.least(func.greatest(vf.confidence, 0), 100), Float) * 0.12
            + cast(func.least(func.greatest(vf.occurrences, 1), 50), Float) * 0.45
            + case((cve_present, 6.0), else_=0.0)
            + cvss_points
            + case((internet_exposed, 6.0), else_=0.0)
            + case((has_fix, 4.0), else_=0.0)
            + recency_points
        ),
    )


def upsert_scan_metadata(
    db: Session,
    *,
    scan_uuid: str,
    reporter_agent_id: str,
    target: str | None,
    tool: str,
    tool_version: str | None,
    status: str,
    started_at: datetime,
    finished_at: datetime | None,
    scope: dict[str, Any],
    config: dict[str, Any],
    stats: dict[str, Any],
    now: datetime,
) -> int | None:
    scan_insert = insert(VulnScanModel).values(
        scan_uuid=scan_uuid,
        reporter_agent_id=reporter_agent_id,
        target=target,
        tool=tool,
        tool_version=tool_version,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        scope=scope,
        config=config,
        stats=stats,
        updated_at=now,
    )
    scan_upsert = scan_insert.on_conflict_do_update(
        index_elements=[VulnScanModel.scan_uuid],
        set_={
            "reporter_agent_id": scan_insert.excluded.reporter_agent_id,
            "target": func.coalesce(scan_insert.excluded.target, VulnScanModel.target),
            "tool": scan_insert.excluded.tool,
            "tool_version": func.coalesce(scan_insert.excluded.tool_version, VulnScanModel.tool_version),
            "status": scan_insert.excluded.status,
            "started_at": func.least(VulnScanModel.started_at, scan_insert.excluded.started_at),
            "finished_at": func.coalesce(scan_insert.excluded.finished_at, VulnScanModel.finished_at),
            "scope": VulnScanModel.scope.op("||")(scan_insert.excluded.scope),
            "config": VulnScanModel.config.op("||")(scan_insert.excluded.config),
            "stats": VulnScanModel.stats.op("||")(scan_insert.excluded.stats),
            "updated_at": now,
        },
    ).returning(VulnScanModel.id)
    row = db.execute(scan_upsert).first()
    return int(row[0]) if row and row[0] is not None else None


def bulk_upsert_findings(db: Session, *, rows: list[dict[str, Any]], auto_reopen: bool, now: datetime) -> None:
    if not rows:
        return
    finding_insert = insert(VulnFindingModel).values(rows)
    excl = finding_insert.excluded
    finding_upsert = finding_insert.on_conflict_do_update(
        index_elements=[VulnFindingModel.asset_key, VulnFindingModel.fingerprint],
        set_={
            "scan_id": func.coalesce(excl.scan_id, VulnFindingModel.scan_id),
            "asset_agent_id": func.coalesce(excl.asset_agent_id, VulnFindingModel.asset_agent_id),
            "reporter_agent_id": func.coalesce(excl.reporter_agent_id, VulnFindingModel.reporter_agent_id),
            "target": func.coalesce(excl.target, VulnFindingModel.target),
            "asset": VulnFindingModel.asset.op("||")(excl.asset),
            "source": excl.source,
            "external_id": func.coalesce(excl.external_id, VulnFindingModel.external_id),
            "severity": case(
                (excl.severity_rank > VulnFindingModel.severity_rank, excl.severity),
                else_=VulnFindingModel.severity,
            ),
            "severity_rank": func.greatest(VulnFindingModel.severity_rank, excl.severity_rank),
            "confidence": func.greatest(VulnFindingModel.confidence, excl.confidence),
            "title": func.coalesce(func.nullif(excl.title, ""), VulnFindingModel.title),
            "description": func.coalesce(excl.description, VulnFindingModel.description),
            "remediation": func.coalesce(excl.remediation, VulnFindingModel.remediation),
            "cve": func.coalesce(excl.cve, VulnFindingModel.cve),
            "cwe": func.coalesce(excl.cwe, VulnFindingModel.cwe),
            "cvss": func.coalesce(excl.cvss, VulnFindingModel.cvss),
            "location": func.coalesce(excl.location, VulnFindingModel.location),
            "tags": case((func.jsonb_array_length(excl.tags) > 0, excl.tags), else_=VulnFindingModel.tags),
            "evidence": VulnFindingModel.evidence.op("||")(excl.evidence),
            "last_seen_at": func.greatest(VulnFindingModel.last_seen_at, excl.last_seen_at),
            "occurrences": VulnFindingModel.occurrences + 1,
            "status": case(
                (
                    and_(literal(bool(auto_reopen)).is_(True), VulnFindingModel.status.in_(["fixed", "resolved"])),
                    literal("open"),
                ),
                else_=VulnFindingModel.status,
            ),
            "updated_at": now,
        },
    )
    db.execute(finding_upsert)


def get_agent_by_agent_id(db: Session, agent_id: str) -> AgentModel | None:
    return db.query(AgentModel).filter(AgentModel.agent_id == agent_id).first()


def add_vuln_scan(db: Session, scan: VulnScanModel) -> None:
    db.add(scan)


def add_agent(db: Session, agent: AgentModel) -> None:
    db.add(agent)


def list_scans_page(
    db: Session,
    *,
    page_size: int,
    cursor_parsed: tuple[datetime, int] | None,
    reporter_agent_id: str | None,
    status_q: str | None,
    tool: str | None,
) -> list[VulnScanModel]:
    stmt = select(VulnScanModel).order_by(VulnScanModel.started_at.desc(), VulnScanModel.id.desc())
    if reporter_agent_id:
        stmt = stmt.where(VulnScanModel.reporter_agent_id == reporter_agent_id)
    if status_q:
        stmt = stmt.where(VulnScanModel.status == status_q.lower())
    if tool:
        stmt = stmt.where(VulnScanModel.tool == tool.lower())

    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                VulnScanModel.started_at < c_ts,
                and_(VulnScanModel.started_at == c_ts, VulnScanModel.id < c_id),
            )
        )

    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def list_findings_page(
    db: Session,
    *,
    page_size: int,
    cursor_parsed: tuple[datetime, int] | None,
    asset_agent_id: str | None,
    reporter_agent_id: str | None,
    status_q: str | None,
    include_suppressed: bool,
    min_severity_rank: int | None,
    cve: str | None,
    query_text: str | None,
) -> list[VulnFindingModel]:
    stmt = select(VulnFindingModel).order_by(VulnFindingModel.last_seen_at.desc(), VulnFindingModel.id.desc())

    if asset_agent_id:
        stmt = stmt.where(VulnFindingModel.asset_agent_id == asset_agent_id)
    if reporter_agent_id:
        stmt = stmt.where(VulnFindingModel.reporter_agent_id == reporter_agent_id)
    if status_q:
        stmt = stmt.where(VulnFindingModel.status == status_q.lower())
    if not include_suppressed:
        stmt = stmt.where(VulnFindingModel.is_suppressed.is_(False))
    if min_severity_rank is not None:
        stmt = stmt.where(VulnFindingModel.severity_rank >= min_severity_rank)
    if cve:
        stmt = stmt.where(VulnFindingModel.cve == cve)

    if query_text:
        q2 = f"%{query_text.strip()}%"
        stmt = stmt.where(
            or_(
                VulnFindingModel.title.ilike(q2),
                VulnFindingModel.target.ilike(q2),
                VulnFindingModel.cve.ilike(q2),
                VulnFindingModel.external_id.ilike(q2),
            )
        )

    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                VulnFindingModel.last_seen_at < c_ts,
                and_(VulnFindingModel.last_seen_at == c_ts, VulnFindingModel.id < c_id),
            )
        )

    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def get_finding_by_id(db: Session, finding_id: int) -> VulnFindingModel | None:
    return db.get(VulnFindingModel, finding_id)


def apply_finding_patch(
    db: Session,
    *,
    row: VulnFindingModel,
    status: str | None,
    is_suppressed: bool | None,
    updated_at: datetime,
) -> None:
    if status is not None:
        row.status = status
    if is_suppressed is not None:
        row.is_suppressed = bool(is_suppressed)
    row.updated_at = updated_at
    db.add(row)


def summary_counts(
    db: Session,
    *,
    since: datetime,
    include_suppressed: bool,
) -> tuple[int, int, dict[str, int], dict[str, int]]:
    conds = [VulnFindingModel.last_seen_at >= since]
    if not include_suppressed:
        conds.append(VulnFindingModel.is_suppressed.is_(False))

    total_open = (
        db.execute(
            select(func.count())
            .select_from(VulnFindingModel)
            .where(*conds)
            .where(VulnFindingModel.status == "open")
        ).scalar_one()
        or 0
    )

    total_suppressed = (
        db.execute(
            select(func.count())
            .select_from(VulnFindingModel)
            .where(VulnFindingModel.last_seen_at >= since)
            .where(VulnFindingModel.is_suppressed.is_(True))
        ).scalar_one()
        or 0
    )

    by_sev_rows = db.execute(
        select(VulnFindingModel.severity, func.count())
        .select_from(VulnFindingModel)
        .where(*conds)
        .group_by(VulnFindingModel.severity)
    ).all()
    by_severity = {str(k or "unknown"): int(v or 0) for (k, v) in by_sev_rows}

    by_status_rows = db.execute(
        select(VulnFindingModel.status, func.count())
        .select_from(VulnFindingModel)
        .where(*conds)
        .group_by(VulnFindingModel.status)
    ).all()
    by_status = {str(k or "unknown"): int(v or 0) for (k, v) in by_status_rows}

    return int(total_open), int(total_suppressed), by_severity, by_status


def posture_data(
    db: Session,
    *,
    now: datetime,
    since: datetime,
    include_suppressed: bool,
    top_n: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    stale_before = now - timedelta(days=30)
    vf = VulnFindingModel
    risk_expr = _risk_score_expr(now, vf).label("risk_score")
    cvss_num = _cvss_numeric_expr(vf).label("cvss_score")
    has_fix = _has_fix_expr(vf).label("has_fix")
    internet_exposed = _internet_exposed_expr(vf).label("internet_exposed")
    exploit_likely = or_(
        _cvss_numeric_expr(vf) >= 7.0,
        _internet_exposed_expr(vf),
        and_(vf.cve.is_not(None), func.btrim(vf.cve) != "", vf.severity_rank >= 3),
    ).label("exploit_likely")

    base_conds = [vf.status == "open", vf.last_seen_at >= since]
    if not include_suppressed:
        base_conds.append(vf.is_suppressed.is_(False))

    base = (
        select(
            vf.id.label("id"),
            vf.asset_key.label("asset_key"),
            vf.asset_agent_id.label("asset_agent_id"),
            vf.target.label("target"),
            vf.title.label("title"),
            vf.cve.label("cve"),
            vf.severity.label("severity"),
            vf.severity_rank.label("severity_rank"),
            vf.confidence.label("confidence"),
            vf.occurrences.label("occurrences"),
            vf.last_seen_at.label("last_seen_at"),
            vf.remediation.label("remediation"),
            vf.cvss.label("cvss"),
            cvss_num,
            has_fix,
            internet_exposed,
            exploit_likely,
            risk_expr,
        )
        .where(*base_conds)
        .subquery("base")
    )

    totals = (
        db.execute(
            select(
                func.count().label("total_open"),
                func.sum(case((base.c.severity == "critical", 1), else_=0)).label("critical_open"),
                func.sum(case((base.c.severity == "high", 1), else_=0)).label("high_open"),
                func.sum(case((base.c.exploit_likely.is_(True), 1), else_=0)).label("exploitable_open"),
                func.sum(case((base.c.has_fix.is_(True), 1), else_=0)).label("fixable_open"),
                func.sum(case((base.c.last_seen_at < stale_before, 1), else_=0)).label("stale_open"),
                func.coalesce(func.avg(base.c.risk_score), 0.0).label("mean_risk"),
                func.coalesce(func.percentile_cont(0.95).within_group(base.c.risk_score), 0.0).label("p95_risk"),
            )
        )
        .mappings()
        .first()
        or {}
    )

    top_rows = db.execute(
        select(
            base.c.id,
            base.c.asset_key,
            base.c.asset_agent_id,
            base.c.target,
            base.c.title,
            base.c.cve,
            base.c.severity,
            base.c.confidence,
            base.c.occurrences,
            base.c.last_seen_at,
            base.c.remediation,
            base.c.cvss,
            base.c.cvss_score,
            base.c.has_fix,
            base.c.internet_exposed,
            base.c.exploit_likely,
            base.c.risk_score,
        )
        .order_by(base.c.risk_score.desc(), base.c.last_seen_at.desc(), base.c.id.desc())
        .limit(int(top_n))
    ).mappings().all()

    asset_rows = db.execute(
        select(
            base.c.asset_key,
            func.max(base.c.asset_agent_id).label("asset_agent_id"),
            func.count().label("open_findings"),
            func.sum(case((base.c.severity_rank >= 3, 1), else_=0)).label("critical_high"),
            func.coalesce(func.max(base.c.risk_score), 0.0).label("max_risk"),
            func.coalesce(func.avg(base.c.risk_score), 0.0).label("avg_risk"),
            func.max(base.c.last_seen_at).label("last_seen_at"),
        )
        .group_by(base.c.asset_key)
        .order_by(
            func.max(base.c.risk_score).desc(),
            func.sum(case((base.c.severity_rank >= 3, 1), else_=0)).desc(),
            func.count().desc(),
        )
        .limit(10)
    ).mappings().all()

    return dict(totals), [dict(r) for r in top_rows], [dict(r) for r in asset_rows]


def commit(db: Session) -> None:
    db.commit()


def refresh(db: Session, row: Any) -> None:
    db.refresh(row)
