from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Float, Text, and_, case, cast, func, literal, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.features.agents.models import AgentModel
from app.features.vuln.domain import (
    derive_legacy_finding_status,
    lifecycle_state_for_phase,
    normalize_finding_observation_state,
    normalize_finding_operator_disposition,
    normalize_scan_lifecycle_state,
    normalize_scan_phase,
    normalize_trigger_source,
    scan_lifecycle_rank,
    scan_phase_rank,
)
from app.features.vuln.models import VulnFindingModel, VulnScanModel


def _cvss_numeric_expr(vf=VulnFindingModel):
    return case(
        (vf.cvss.op("~")(r"^[0-9]+(\.[0-9]+)?$"), cast(vf.cvss, Float)),
        else_=0.0,
    )


def _json_float_expr(expr):
    return case(
        (expr.op("~")(r"^[0-9]+(\.[0-9]+)?$"), cast(expr, Float)),
        else_=0.0,
    )


def _json_bool_expr(expr):
    return func.lower(func.coalesce(expr, "")) == "true"


def _has_fix_expr(vf=VulnFindingModel):
    return or_(
        vf.evidence["osv"]["fixed"].astext.is_not(None),
        and_(vf.remediation.is_not(None), func.btrim(vf.remediation) != ""),
    )


def _surface_score_expr(vf=VulnFindingModel):
    return func.greatest(
        _json_float_expr(vf.evidence["analysis"]["exposure_score"].astext),
        _json_float_expr(vf.asset["exposure"]["surface_score"].astext),
    )


def _observed_external_expr(vf=VulnFindingModel):
    return _json_bool_expr(vf.asset["exposure"]["has_exposed_ports"].astext)


def _package_relevant_expr(vf=VulnFindingModel):
    return _json_bool_expr(vf.evidence["analysis"]["package_network_facing"].astext)


def _internet_exposed_expr(vf=VulnFindingModel):
    network_attack_vector = or_(
        func.upper(func.coalesce(vf.cvss, "")).like("%AV:N%"),
        _json_bool_expr(vf.evidence["analysis"]["network_attack_vector"].astext),
    )
    return or_(
        _observed_external_expr(vf),
        _package_relevant_expr(vf),
        network_attack_vector,
        _surface_score_expr(vf) >= 60.0,
    )


def _risk_score_expr(now: datetime, vf=VulnFindingModel):
    cvss_num = _cvss_numeric_expr(vf)
    cve_present = and_(vf.cve.is_not(None), func.btrim(vf.cve) != "")
    has_fix = _has_fix_expr(vf)
    internet_exposed = _internet_exposed_expr(vf)
    observed_external = _observed_external_expr(vf)
    package_relevant = _package_relevant_expr(vf)
    surface_score = _surface_score_expr(vf)

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

    recurrence_points = case(
        (vf.occurrences >= 5, 8.0),
        (vf.occurrences >= 2, 4.0),
        else_=0.0,
    )

    surface_points = case(
        (surface_score >= 60.0, 6.0),
        (surface_score >= 30.0, 3.0),
        else_=0.0,
    )

    return func.least(
        100.0,
        (
            cast(vf.severity_rank, Float) * 17.0
            + cast(func.least(func.greatest(vf.confidence, 0), 100), Float) * 0.12
            + case((cve_present, 6.0), else_=0.0)
            + cvss_points
            + case((observed_external, 12.0), else_=0.0)
            + case((and_(internet_exposed, observed_external.is_(False)), 6.0), else_=0.0)
            + case((package_relevant, 6.0), else_=0.0)
            + surface_points
            + case((has_fix, 6.0), else_=0.0)
            + recurrence_points
            + recency_points
        ),
    )


def _merge_json(existing: Any, incoming: dict[str, Any]) -> dict[str, Any]:
    base = dict(existing or {})
    if incoming:
        base.update(incoming)
    return base


def _normalize_phase_timestamps(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in value.items():
        key = str(k or "").strip().lower()
        val = str(v or "").strip()
        if not key or not val:
            continue
        out[key] = val
    return out


def _isoformat(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat()


def _pick_earliest(existing: datetime | None, incoming: datetime | None) -> datetime | None:
    if existing is None:
        return incoming
    if incoming is None:
        return existing
    return incoming if incoming < existing else existing


def _pick_latest(existing: datetime | None, incoming: datetime | None) -> datetime | None:
    if existing is None:
        return incoming
    if incoming is None:
        return existing
    return incoming if incoming > existing else existing


def _should_apply_scan_state(existing_state: str | None, incoming_state: str | None) -> bool:
    existing_norm = normalize_scan_lifecycle_state(existing_state)
    incoming_norm = normalize_scan_lifecycle_state(incoming_state)
    if existing_norm in {"completed", "failed", "cancelled"} and incoming_norm not in {"completed", "failed", "cancelled"}:
        return False
    return scan_lifecycle_rank(incoming_norm) >= scan_lifecycle_rank(existing_norm)


def _should_apply_scan_phase(existing_phase: str | None, incoming_phase: str | None) -> bool:
    existing_norm = normalize_scan_phase(existing_phase)
    incoming_norm = normalize_scan_phase(incoming_phase)
    if existing_norm in {"completed", "failed", "cancelled"} and incoming_norm not in {"completed", "failed", "cancelled"}:
        return False
    return scan_phase_rank(incoming_norm) >= scan_phase_rank(existing_norm)


def get_scan_by_uuid(db: Session, scan_uuid: str) -> VulnScanModel | None:
    return db.execute(select(VulnScanModel).where(VulnScanModel.scan_uuid == scan_uuid)).scalar_one_or_none()


def upsert_scan_metadata(
    db: Session,
    *,
    scan_uuid: str,
    reporter_agent_id: str,
    target: str | None,
    tool: str,
    tool_version: str | None,
    status: str | None,
    lifecycle_state: str | None,
    current_phase: str | None,
    queued_at: datetime | None,
    acknowledged_at: datetime | None,
    started_at: datetime | None,
    finished_at: datetime | None,
    last_progress_at: datetime | None,
    trigger_source: str | None,
    error_summary: str | None,
    scope: dict[str, Any],
    config: dict[str, Any],
    stats: dict[str, Any],
    phase_timestamps: dict[str, str],
    now: datetime,
) -> VulnScanModel:
    requested_state = normalize_scan_lifecycle_state(lifecycle_state or status or lifecycle_state_for_phase(current_phase))
    requested_phase = normalize_scan_phase(current_phase, fallback_state=requested_state)
    progress_at = last_progress_at or finished_at or started_at or acknowledged_at or queued_at or now
    inferred_started_at = started_at
    if inferred_started_at is None and requested_state in {"running", "completed", "failed", "cancelled"}:
        inferred_started_at = progress_at
    source = normalize_trigger_source(
        trigger_source,
        manual_trigger=bool(scope.get("manual_trigger") or config.get("manual_trigger")),
    )
    row = get_scan_by_uuid(db, scan_uuid)
    if row is None:
        row = VulnScanModel(
            scan_uuid=scan_uuid,
            reporter_agent_id=reporter_agent_id,
            target=target,
            tool=tool,
            tool_version=tool_version,
            status=requested_state,
            lifecycle_state=requested_state,
            current_phase=requested_phase,
            queued_at=queued_at or started_at or progress_at,
            acknowledged_at=acknowledged_at,
            started_at=inferred_started_at,
            finished_at=finished_at,
            last_progress_at=progress_at,
            trigger_source=source,
            error_summary=error_summary,
            scope=dict(scope or {}),
            config=dict(config or {}),
            stats=dict(stats or {}),
            phase_timestamps=_normalize_phase_timestamps(phase_timestamps),
            updated_at=now,
        )
        db.add(row)
    else:
        row.reporter_agent_id = reporter_agent_id or row.reporter_agent_id
        row.target = target or row.target
        row.tool = tool or row.tool
        row.tool_version = tool_version or row.tool_version
        row.queued_at = _pick_earliest(row.queued_at, queued_at or started_at or progress_at) or progress_at
        row.acknowledged_at = _pick_earliest(row.acknowledged_at, acknowledged_at)
        row.started_at = _pick_earliest(row.started_at, inferred_started_at)
        row.finished_at = _pick_latest(row.finished_at, finished_at)
        row.last_progress_at = _pick_latest(row.last_progress_at, progress_at) or progress_at
        row.trigger_source = source or row.trigger_source
        row.scope = _merge_json(row.scope, dict(scope or {}))
        row.config = _merge_json(row.config, dict(config or {}))
        row.stats = _merge_json(row.stats, dict(stats or {}))
        if error_summary is not None:
            row.error_summary = error_summary
        elif requested_state == "completed":
            row.error_summary = None

        if _should_apply_scan_state(row.lifecycle_state, requested_state):
            row.lifecycle_state = requested_state
            row.status = requested_state
        if _should_apply_scan_phase(row.current_phase, requested_phase):
            row.current_phase = requested_phase

        merged_phase_timestamps = _normalize_phase_timestamps(row.phase_timestamps)
        merged_phase_timestamps.update(_normalize_phase_timestamps(phase_timestamps))
        row.phase_timestamps = merged_phase_timestamps
        row.updated_at = now

    phase_map = _normalize_phase_timestamps(row.phase_timestamps)
    for phase_name, at in [
        ("queued", row.queued_at),
        ("acknowledged", row.acknowledged_at),
        ("running", row.started_at),
        (requested_phase, progress_at),
        (row.current_phase, row.last_progress_at),
        (row.lifecycle_state, row.finished_at or row.last_progress_at),
    ]:
        key = normalize_scan_phase(phase_name, fallback_state=phase_name)
        val = _isoformat(at)
        if val and key not in phase_map:
            phase_map[key] = val
    if row.finished_at is not None and row.lifecycle_state in {"completed", "failed", "cancelled"}:
        phase_map[row.lifecycle_state] = _isoformat(row.finished_at) or phase_map.get(row.lifecycle_state, "")
    row.phase_timestamps = phase_map
    row.updated_at = now
    db.add(row)
    db.flush()
    return row


def bulk_upsert_findings(db: Session, *, rows: list[dict[str, Any]], auto_reopen: bool, now: datetime) -> list[int]:
    if not rows:
        return []

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
            "observation_state": literal("observed"),
            "status": case(
                (VulnFindingModel.operator_disposition == "suppressed", literal("ignored")),
                (VulnFindingModel.operator_disposition == "accepted_risk", literal("accepted")),
                else_=literal("open"),
            ),
            "is_suppressed": case(
                (VulnFindingModel.operator_disposition == "suppressed", literal(True)),
                else_=literal(False),
            ),
            "updated_at": now,
        },
    ).returning(VulnFindingModel.id)
    return [int(x) for x in db.execute(finding_upsert).scalars().all()]


def reconcile_resolved_findings(
    db: Session,
    *,
    reporter_agent_id: str,
    observed_fingerprints: list[str],
    sources: list[str],
    now: datetime,
) -> list[int]:
    if not reporter_agent_id:
        return []

    stmt = (
        update(VulnFindingModel)
        .where(VulnFindingModel.reporter_agent_id == reporter_agent_id)
        .where(VulnFindingModel.observation_state.in_(["observed", "awaiting_verification"]))
        .values(
            observation_state="resolved",
            status="resolved",
            updated_at=now,
        )
    )
    if sources:
        stmt = stmt.where(VulnFindingModel.source.in_(sources))
    if observed_fingerprints:
        stmt = stmt.where(VulnFindingModel.fingerprint.not_in(observed_fingerprints))
    stmt = stmt.returning(VulnFindingModel.id)
    return [int(x) for x in db.execute(stmt).scalars().all()]


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
    stmt = select(VulnScanModel).order_by(VulnScanModel.queued_at.desc(), VulnScanModel.id.desc())
    if reporter_agent_id:
        stmt = stmt.where(VulnScanModel.reporter_agent_id == reporter_agent_id)
    if status_q:
        q = status_q.lower()
        stmt = stmt.where(
            or_(
                VulnScanModel.status == q,
                VulnScanModel.lifecycle_state == q,
                VulnScanModel.current_phase == q,
            )
        )
    if tool:
        stmt = stmt.where(VulnScanModel.tool == tool.lower())

    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                VulnScanModel.queued_at < c_ts,
                and_(VulnScanModel.queued_at == c_ts, VulnScanModel.id < c_id),
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
    observation_state_q: str | None,
    operator_disposition_q: str | None,
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
    if observation_state_q:
        stmt = stmt.where(VulnFindingModel.observation_state == observation_state_q.lower())
    if operator_disposition_q:
        stmt = stmt.where(VulnFindingModel.operator_disposition == operator_disposition_q.lower())
    if not include_suppressed:
        stmt = stmt.where(VulnFindingModel.operator_disposition != "suppressed")
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
                VulnFindingModel.asset_key.ilike(q2),
                VulnFindingModel.location.ilike(q2),
                VulnFindingModel.cve.ilike(q2),
                VulnFindingModel.external_id.ilike(q2),
                cast(VulnFindingModel.asset, Text).ilike(q2),
                cast(VulnFindingModel.evidence, Text).ilike(q2),
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


def get_findings_by_ids(db: Session, finding_ids: list[int]) -> list[VulnFindingModel]:
    if not finding_ids:
        return []
    rows = db.execute(
        select(VulnFindingModel).where(VulnFindingModel.id.in_([int(x) for x in finding_ids]))
    ).scalars().all()
    order = {int(fid): idx for idx, fid in enumerate(finding_ids)}
    rows.sort(key=lambda row: order.get(int(row.id), len(order)))
    return rows


def apply_finding_patch(
    db: Session,
    *,
    row: VulnFindingModel,
    observation_state: str | None,
    operator_disposition: str | None,
    updated_at: datetime,
) -> None:
    next_observation_state = normalize_finding_observation_state(observation_state or row.observation_state)
    next_operator_disposition = normalize_finding_operator_disposition(
        operator_disposition or row.operator_disposition,
        is_suppressed=(operator_disposition == "suppressed"),
    )
    row.observation_state = next_observation_state
    row.operator_disposition = next_operator_disposition
    row.status = derive_legacy_finding_status(next_observation_state, next_operator_disposition)
    row.is_suppressed = next_operator_disposition == "suppressed"
    row.updated_at = updated_at
    db.add(row)


def summary_counts(
    db: Session,
    *,
    since: datetime,
    include_suppressed: bool,
) -> tuple[int, int, int, int, int, dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
    conds = [VulnFindingModel.last_seen_at >= since]
    if not include_suppressed:
        conds.append(VulnFindingModel.operator_disposition != "suppressed")

    total_open = (
        db.execute(
            select(func.count())
            .select_from(VulnFindingModel)
            .where(*conds)
            .where(VulnFindingModel.status == "open")
        ).scalar_one()
        or 0
    )
    total_observed = (
        db.execute(
            select(func.count())
            .select_from(VulnFindingModel)
            .where(*conds)
            .where(VulnFindingModel.observation_state == "observed")
        ).scalar_one()
        or 0
    )
    total_awaiting_verification = (
        db.execute(
            select(func.count())
            .select_from(VulnFindingModel)
            .where(*conds)
            .where(VulnFindingModel.observation_state == "awaiting_verification")
        ).scalar_one()
        or 0
    )
    total_resolved = (
        db.execute(
            select(func.count())
            .select_from(VulnFindingModel)
            .where(*conds)
            .where(VulnFindingModel.observation_state == "resolved")
        ).scalar_one()
        or 0
    )
    total_suppressed = (
        db.execute(
            select(func.count())
            .select_from(VulnFindingModel)
            .where(VulnFindingModel.last_seen_at >= since)
            .where(VulnFindingModel.operator_disposition == "suppressed")
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

    by_observation_rows = db.execute(
        select(VulnFindingModel.observation_state, func.count())
        .select_from(VulnFindingModel)
        .where(*conds)
        .group_by(VulnFindingModel.observation_state)
    ).all()
    by_observation_state = {str(k or "unknown"): int(v or 0) for (k, v) in by_observation_rows}

    by_disposition_rows = db.execute(
        select(VulnFindingModel.operator_disposition, func.count())
        .select_from(VulnFindingModel)
        .where(*conds)
        .group_by(VulnFindingModel.operator_disposition)
    ).all()
    by_disposition = {str(k or "unknown"): int(v or 0) for (k, v) in by_disposition_rows}

    return (
        int(total_open),
        int(total_observed),
        int(total_awaiting_verification),
        int(total_resolved),
        int(total_suppressed),
        by_severity,
        by_status,
        by_observation_state,
        by_disposition,
    )


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

    base_conds = [vf.observation_state == "observed", vf.last_seen_at >= since]
    if not include_suppressed:
        base_conds.append(vf.operator_disposition != "suppressed")

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
            vf.source.label("source"),
            vf.location.label("location"),
            vf.asset.label("asset"),
            vf.evidence.label("evidence"),
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
            base.c.source,
            base.c.location,
            base.c.asset,
            base.c.evidence,
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
