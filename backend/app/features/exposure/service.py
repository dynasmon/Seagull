from __future__ import annotations

import asyncio
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence
from urllib.parse import unquote

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.api.pagination import encode_cursor, make_cursor_ts_id, parse_cursor_ts_id
from app.core.audit import audit_actor, write_audit_event
from app.core.config import settings
from app.core.observability import observe_hist
from app.features.auth.session import PortalPrincipal
from app.features.exposure import realtime as exposure_realtime
from app.features.exposure import repository
from app.features.exposure.domain.constants import (
    EDGE_TYPES,
    NODE_TYPE_ASSET,
    NODE_TYPES,
    RC_ACTIVE_ALERT,
    RC_ATTACK_CHAIN_PROGRESSION,
    RC_BRUTE_FORCE_ACTIVITY,
    RC_CRITICAL_CVE,
    RC_EXPLOITABILITY_SIGNAL,
    RC_LATERAL_MOVEMENT_SIGNAL,
    RC_PERSISTENCE_SIGNAL,
    RC_SENSITIVE_FILE_CHANGE,
    RC_STALE_AGENT,
    RC_STALE_INVENTORY,
    RC_SUSPICIOUS_PROCESS,
    RC_VULNERABLE_PACKAGE,
)
from app.features.exposure.domain.evidence import (
    count_evidence_by_source,
    derive_aggregate_confidence,
    evidence_refs_to_list,
)
from app.features.exposure.domain.explain import explain_score
from app.features.exposure.domain.normalization import (
    asset_status_from_age,
    normalize_evidence_ref,
    normalize_finding_status,
    normalize_finding_type,
    normalize_severity,
    severity_from_score,
    stable_hash,
    validate_asset_key,
)
from app.features.exposure.domain.recommendations import generate_recommendations
from app.features.exposure.domain.scoring import ScoringInputs, compute_risk_score
from app.features.exposure.domain.types import EdgeInput, EvidenceRef, FindingInput, NodeInput, PostureInput
from app.features.exposure.models import (
    ExposureAssetPostureModel,
    ExposureEdgeModel,
    ExposureFindingModel,
    ExposureNodeModel,
    ExposureScoreHistoryModel,
)
from app.features.exposure.schemas import (
    EvidenceRefOut,
    ExposureAssetDetailOut,
    ExposureAssetPostureOut,
    ExposureAttackPathOut,
    ExposureAttackPathStageOut,
    ExposureCountOut,
    ExposureFindingOut,
    ExposureFindingsQuery,
    ExposureGraphEdgeOut,
    ExposureGraphHealthOut,
    ExposureGraphLegendOut,
    ExposureGraphNodeOut,
    ExposureGraphOut,
    ExposureGraphQuery,
    ExposureInvestigationResultOut,
    ExposureLinkedAlertOut,
    ExposureLinkedAttackChainCaseOut,
    ExposureLinkedAttackChainStepOut,
    ExposureLinkedInvestigationOut,
    ExposureLinkedResponseActionOut,
    ExposureLinkedVulnerabilityOut,
    ExposurePathsQuery,
    ExposureRecalculateOut,
    ExposureScoreHistoryPointOut,
    ExposureSummaryOut,
    ExposureTriageResponseActionOut,
    RecommendationOut,
    ScoreBreakdownOut,
    ScoreExplanationOut,
)
from app.features.investigations import public as investigations_public
from app.features.response import public as response_public
from app.shared.analytics import AnalyticalReadModel, register_read_model, serve_read_model
from app.shared.indexing.offset_store import set_offset
from app.shared.schemas import CursorPage

_UTC = timezone.utc
_OFFSET_NAME = "exposure_graph_events_v1"
_TOP_SUMMARY_COUNTS = 5
_MAX_DETAIL_FINDINGS = 12
_MAX_DETAIL_LINKED = 10
_MAX_PATH_EVIDENCE = 8
_GRAPH_DEPTH_HARD_MAX = 4
_SECRET_KEY_PARTS = ("secret", "token", "password", "passwd", "authorization", "cookie", "bearer", "key")
_TERMINAL_STATUS = {"resolved", "suppressed", "closed", "cancelled", "expired", "success", "failed"}
_ATTACK_PATH_REASON_PRIORITY = (
    RC_ATTACK_CHAIN_PROGRESSION,
    RC_LATERAL_MOVEMENT_SIGNAL,
    RC_PERSISTENCE_SIGNAL,
    RC_SUSPICIOUS_PROCESS,
    RC_BRUTE_FORCE_ACTIVITY,
    RC_EXPLOITABILITY_SIGNAL,
    RC_CRITICAL_CVE,
    RC_ACTIVE_ALERT,
    RC_SENSITIVE_FILE_CHANGE,
    RC_VULNERABLE_PACKAGE,
)
_ATTACK_PATH_STAGE_MAP: dict[str, tuple[str, str]] = {
    RC_BRUTE_FORCE_ACTIVITY: ("initial_access", "Brute-force authentication activity"),
    RC_EXPLOITABILITY_SIGNAL: ("execution", "Known-exploitable vulnerability"),
    RC_CRITICAL_CVE: ("execution", "Critical vulnerability exposure"),
    RC_ACTIVE_ALERT: ("execution", "Active security alert"),
    RC_SUSPICIOUS_PROCESS: ("execution", "Suspicious process execution"),
    RC_PERSISTENCE_SIGNAL: ("persistence", "Persistence mechanism detected"),
    RC_SENSITIVE_FILE_CHANGE: ("defense_evasion", "Sensitive file modification"),
    RC_LATERAL_MOVEMENT_SIGNAL: ("lateral_movement", "Lateral movement signal"),
    RC_ATTACK_CHAIN_PROGRESSION: ("attack_chain", "Attack-chain progression"),
    RC_VULNERABLE_PACKAGE: ("exposure", "Vulnerable package present"),
}
_EDGE_TYPE_LABELS = {
    "has_cve": "Asset to vulnerability",
    "has_package": "Asset to package",
    "has_service": "Asset to service",
    "communicates_with": "Network communication",
    "executed_process": "Process execution",
    "modified_file": "File modification",
    "triggered_alert": "Alert evidence",
    "part_of_attack_chain": "Attack chain progression",
    "part_of_investigation": "Investigation context",
    "triggered_response_action": "Operational response",
    "lateral_movement_to": "Lateral movement",
    "exploited_by": "Exploitation relationship",
}


def _utc_now() -> datetime:
    return datetime.now(_UTC)


def _to_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_UTC)
    return dt.astimezone(_UTC)


def _raise_api_error(status_code: int, code: str, message: str, *, context: dict[str, Any] | None = None) -> None:
    raise HTTPException(status_code=status_code, detail={"code": code, "message": message, "context": context or {}})


def decode_and_validate_asset_key(raw_asset_key: str) -> str:
    decoded = unquote(str(raw_asset_key or "")).strip()
    if len(decoded) > 256:
        _raise_api_error(400, "invalid_asset_key", "asset_key is too long")
    if not validate_asset_key(decoded):
        _raise_api_error(400, "invalid_asset_key", "asset_key format is invalid")
    return decoded


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
    status = asset_status_from_age(last_seen_at) if last_seen_at else "unknown"

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

    before = repository.get_asset_posture(db, asset_key)
    row = repository.upsert_asset_posture(db, posture)
    if _posture_changed(before, row):
        exposure_realtime.publish_asset_updated(row)
        exposure_realtime.publish_summary_updated(updated_at=row.updated_at, asset_key=row.asset_key, reason="asset_upsert")
    return row


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
    before = repository.get_finding(db, finding.finding_key)
    row = repository.upsert_finding(db, finding)
    if _finding_changed(before, row):
        exposure_realtime.publish_finding_updated(row)
        exposure_realtime.publish_summary_updated(updated_at=row.updated_at, asset_key=row.asset_key, reason="finding_upsert")
    return row


def get_asset_posture(db: Session, asset_key: str) -> ExposureAssetPostureModel | None:
    return repository.get_asset_posture(db, asset_key)


def list_assets(db: Session, *, params) -> CursorPage[ExposureAssetPostureOut]:
    cursor = _parse_assets_cursor(params.cursor, expected_sort=params.sort) if params.cursor else None
    rows = repository.list_assets_page(
        db,
        page_size=params.page_size,
        q=params.q,
        severity=params.severity,
        min_score=params.min_score,
        agent_id=params.agent_id,
        status=params.status,
        reason_code=params.reason_code,
        has_attack_chain=params.has_attack_chain,
        has_critical_vuln=params.has_critical_vuln,
        has_persistence_signal=params.has_persistence_signal,
        sort=params.sort,
        cursor=cursor,
    )
    has_more = len(rows) > params.page_size
    items = rows[: params.page_size]
    next_cursor = _make_assets_cursor(items[-1], sort=params.sort) if has_more and items else None
    return CursorPage(items=[_posture_out(row) for row in items], next_cursor=next_cursor, has_more=has_more)


def get_summary(db: Session) -> ExposureSummaryOut:
    metrics = repository.exposure_summary_metrics(db)
    reason_counter: Counter[str] = Counter()
    recommendation_counter: Counter[str] = Counter()
    active_attack_paths = 0
    for reason_codes, recommendations, attack_chain_score in repository.list_posture_vectors(db):
        if attack_chain_score > 0 or _has_attack_path_reason(reason_codes):
            active_attack_paths += 1
        for code in reason_codes:
            if code:
                reason_counter[str(code)] += 1
        for item in recommendations:
            if not isinstance(item, dict):
                continue
            action = str(item.get("action") or item.get("rec_type") or "").strip()
            if action:
                recommendation_counter[action] += 1
    top_reason_codes = [
        ExposureCountOut(key=key, count=count)
        for key, count in reason_counter.most_common(_TOP_SUMMARY_COUNTS)
    ]
    top_recommendations = [
        ExposureCountOut(key=key, count=count)
        for key, count in recommendation_counter.most_common(_TOP_SUMMARY_COUNTS)
    ]
    return ExposureSummaryOut(
        total_assets=metrics["total_assets"],
        critical_assets=metrics["critical_assets"],
        high_assets=metrics["high_assets"],
        medium_assets=metrics["medium_assets"],
        low_assets=metrics["low_assets"],
        informational_assets=metrics["informational_assets"],
        avg_risk_score=round(float(metrics["avg_risk_score"] or 0.0), 2),
        max_risk_score=metrics["max_risk_score"],
        active_findings=metrics["active_findings"],
        active_attack_paths=max(active_attack_paths, int(metrics["active_attack_paths"] or 0)),
        stale_agents=metrics["stale_agents"],
        stale_inventory_assets=metrics["stale_inventory_assets"],
        top_reason_codes=top_reason_codes,
        top_recommendations=top_recommendations,
        updated_at=_to_utc(metrics["updated_at"]),
    )


def _exposure_summary_cache_key(params: dict) -> str:
    return "seagull:exposure:summary:v1"


def _resolve_exposure_summary_blocking() -> ExposureSummaryOut:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return get_summary(db)
    finally:
        db.close()


async def _compute_exposure_summary(params: dict) -> dict:
    payload = await asyncio.to_thread(_resolve_exposure_summary_blocking)
    return payload.model_dump(mode="json")


EXPOSURE_SUMMARY_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="exposure_summary",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_EXPOSURE_SUMMARY_FRESH_SECONDS", 30) or 30),
        stale_s=int(getattr(settings, "SEAGULL_EXPOSURE_SUMMARY_STALE_SECONDS", 300) or 300),
        key_builder=_exposure_summary_cache_key,
        compute=_compute_exposure_summary,
    )
)


async def get_exposure_summary_async() -> tuple[dict, str, str]:
    started = time.perf_counter()
    payload, etag, outcome = await serve_read_model(EXPOSURE_SUMMARY_READ_MODEL, {})
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/exposure/summary",
        source=str(meta.get("source") or "compute"),
    )
    return payload, etag, outcome


def get_asset_detail(db: Session, *, asset_key: str) -> ExposureAssetDetailOut:
    row = repository.get_asset_posture(db, asset_key)
    if row is None:
        _raise_api_error(404, "asset_not_found", "Asset posture not found", context={"asset_key": asset_key})

    posture = _posture_out(row)
    score_breakdown = _score_breakdown_from_row(row)
    score_explanation = _score_explanation_out(
        explain_score(
            risk_score=row.risk_score,
            severity=row.severity,
            confidence=row.confidence,
            breakdown=_score_breakdown_dataclass(row),
            reason_codes=list(row.reason_codes or []),
        )
    )
    findings = repository.list_findings_for_asset(db, asset_key=asset_key, limit=_MAX_DETAIL_FINDINGS, active_only=False)
    inventory_context = repository.get_inventory_context(db, agent_id=row.agent_id) if row.agent_id else {}
    lookback = _to_utc(row.updated_at) or _utc_now()
    alerts = repository.list_alerts_for_asset(
        db,
        agent_id=row.agent_id,
        asset_ips=inventory_context.get("ip_addresses") or [],
        hostname=inventory_context.get("hostname"),
        limit=_MAX_DETAIL_LINKED,
        since=lookback - timedelta(days=14),
    )
    vulnerabilities = repository.list_vulnerabilities_for_asset(
        db,
        asset_key=asset_key,
        limit=_MAX_DETAIL_LINKED,
        active_only=False,
    )
    attack_cases = repository.list_attack_chain_cases_for_agent(
        db,
        agent_id=row.agent_id,
        open_only=False,
        limit=4,
    ) if row.agent_id else []
    case_steps = repository.list_attack_chain_steps_for_cases(
        db,
        case_ids=[int(case.id) for case in attack_cases],
        limit=24,
    )
    investigations = repository.list_investigations_for_asset(
        db,
        asset_key=asset_key,
        agent_id=row.agent_id,
        limit=_MAX_DETAIL_LINKED,
    )
    response_actions = repository.list_response_actions_for_agent(
        db,
        agent_id=row.agent_id,
        limit=_MAX_DETAIL_LINKED,
    ) if row.agent_id else []
    latest_results = repository.latest_response_results_for_actions(
        db,
        action_ids=[int(action.id) for action in response_actions],
    )
    history = repository.list_score_history(db, asset_key=asset_key, limit=60)
    history_points = [_score_history_out(item) for item in reversed(history)]
    case_steps_by_case: dict[int, list[Any]] = {}
    for step in case_steps:
        case_steps_by_case.setdefault(int(step.case_id), []).append(step)

    return ExposureAssetDetailOut(
        posture=posture,
        score_breakdown=score_breakdown,
        score_explanation=score_explanation,
        reason_codes=list(row.reason_codes or []),
        top_findings=[_finding_out(item) for item in findings],
        top_recommendations=[_recommendation_out(item) for item in list(row.top_recommendations or [])[:5]],
        linked_attack_chain_cases=[
            _attack_chain_case_out(case, case_steps_by_case.get(int(case.id), []))
            for case in attack_cases
        ],
        linked_alerts=[_alert_out(item) for item in alerts],
        linked_vulnerabilities=[_vulnerability_out(item) for item in vulnerabilities],
        linked_investigations=[_investigation_out(item) for item in investigations],
        linked_response_actions=[_response_action_out(item, latest_results.get(int(item.id))) for item in response_actions],
        recent_score_history=history_points,
        updated_at=_to_utc(row.updated_at) or _utc_now(),
    )


def get_asset_graph(db: Session, *, asset_key: str, params: ExposureGraphQuery) -> ExposureGraphOut:
    posture = repository.get_asset_posture(db, asset_key)
    if posture is None:
        _raise_api_error(404, "asset_not_found", "Asset posture not found", context={"asset_key": asset_key})

    depth = max(1, min(int(params.depth), _GRAPH_DEPTH_HARD_MAX))
    max_nodes = max(1, min(int(params.max_nodes), exposure_realtime.graph_nodes_hard_limit()))
    max_edges = max(1, min(int(params.max_edges), exposure_realtime.graph_edges_hard_limit()))
    node_types = [value for value in params.node_types if value in NODE_TYPES]
    edge_types = [value for value in params.edge_types if value in EDGE_TYPES]

    raw_nodes = repository.list_graph_nodes(
        db,
        asset_key=asset_key,
        node_types=node_types or None,
        min_confidence=params.min_confidence,
        limit=max_nodes * 4,
    )
    raw_edges = repository.list_graph_edges(
        db,
        asset_key=asset_key,
        edge_types=edge_types or None,
        min_confidence=params.min_confidence,
        limit=max_edges * 4,
    )
    root_key = _asset_root_node_key(asset_key)
    node_map = {row.node_key: row for row in raw_nodes if params.include_resolved or not _is_terminal_metadata(row.properties)}
    edge_rows = [
        row
        for row in raw_edges
        if params.include_resolved or not _is_terminal_metadata(row.properties)
    ]
    if root_key not in node_map:
        node_map[root_key] = _synthetic_asset_node(posture)

    adjacency: dict[str, list[ExposureEdgeModel]] = {}
    for edge in edge_rows:
        adjacency.setdefault(edge.source_node_key, []).append(edge)
        adjacency.setdefault(edge.target_node_key, []).append(edge)

    ordered_node_keys: list[str] = []
    seen: set[str] = {root_key}
    frontier: list[tuple[str, int]] = [(root_key, 0)]
    while frontier and len(ordered_node_keys) < max_nodes:
        node_key, node_depth = frontier.pop(0)
        if node_key not in ordered_node_keys:
            ordered_node_keys.append(node_key)
        if node_depth >= depth:
            continue
        for edge in adjacency.get(node_key, []):
            for neighbor in (edge.source_node_key, edge.target_node_key):
                if neighbor in seen or neighbor not in node_map:
                    continue
                seen.add(neighbor)
                frontier.append((neighbor, node_depth + 1))

    selected_keys = set(ordered_node_keys[:max_nodes])
    selected_nodes = [node_map[key] for key in ordered_node_keys if key in selected_keys]
    selected_edges = [
        edge
        for edge in edge_rows
        if edge.source_node_key in selected_keys and edge.target_node_key in selected_keys
    ][:max_edges]
    focus_keys = [
        row.node_key
        for row in sorted(
            [node for node in selected_nodes if node.node_key != root_key],
            key=lambda item: (item.risk_score, item.confidence, _to_utc(item.last_seen_at) or datetime.min.replace(tzinfo=_UTC)),
            reverse=True,
        )[:5]
    ]
    return ExposureGraphOut(
        root_node_key=root_key,
        recommended_focus_node_keys=focus_keys,
        nodes=[_graph_node_out(node) for node in selected_nodes],
        edges=[_graph_edge_out(edge) for edge in selected_edges],
        legend=_graph_legend(),
        graph_health=ExposureGraphHealthOut(
            depth_applied=depth,
            max_nodes_applied=max_nodes,
            max_edges_applied=max_edges,
            node_count=len(selected_nodes),
            edge_count=len(selected_edges),
            nodes_truncated=len(raw_nodes) > len(selected_nodes),
            edges_truncated=len(raw_edges) > len(selected_edges),
            posture_updated_at=_to_utc(posture.updated_at),
            stale_agent=RC_STALE_AGENT in list(posture.reason_codes or []),
            stale_inventory=RC_STALE_INVENTORY in list(posture.reason_codes or []),
        ),
    )


def list_paths(db: Session, *, params: ExposurePathsQuery) -> CursorPage[ExposureAttackPathOut]:
    cursor = _parse_assets_cursor(params.cursor, expected_sort="risk_desc") if params.cursor else None
    collected: list[ExposureAssetPostureModel] = []
    local_cursor = cursor
    attempts = 0
    while len(collected) < params.page_size + 1 and attempts < 5:
        attempts += 1
        batch = repository.list_assets_page(
            db,
            page_size=max(params.page_size * 2, 20),
            q=None,
            severity=params.severity,
            min_score=params.min_score,
            agent_id=params.agent_id,
            status=None,
            reason_code=params.reason_code,
            has_attack_chain=None,
            has_critical_vuln=None,
            has_persistence_signal=None,
            sort="risk_desc",
            cursor=local_cursor,
        )
        if not batch:
            break
        for row in batch:
            if _is_attack_path_candidate(row):
                collected.append(row)
                if len(collected) >= params.page_size + 1:
                    break
        if len(batch) <= max(params.page_size * 2, 20):
            break
        local_cursor = _parse_assets_cursor(_make_assets_cursor(batch[min(len(batch), max(params.page_size * 2, 20)) - 1], sort="risk_desc"), expected_sort="risk_desc")
    has_more = len(collected) > params.page_size
    items = collected[: params.page_size]
    next_cursor = _make_assets_cursor(items[-1], sort="risk_desc") if has_more and items else None
    return CursorPage(
        items=[_build_attack_path(db, row) for row in items],
        next_cursor=next_cursor,
        has_more=has_more,
    )


def _exposure_paths_cache_key(params: dict) -> str:
    return (
        "seagull:exposure:paths:v1:"
        f"ps={int(params['page_size'])}:c={str(params.get('cursor') or '*')}:"
        f"sev={str(params.get('severity') or '*')}:a={str(params.get('agent_id') or '*')}:"
        f"ms={str(params.get('min_score') if params.get('min_score') is not None else '*')}:"
        f"rc={str(params.get('reason_code') or '*')}"
    )


def _resolve_exposure_paths_blocking(*, params: ExposurePathsQuery) -> CursorPage[ExposureAttackPathOut]:
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        return list_paths(db, params=params)
    finally:
        db.close()


async def _compute_exposure_paths(params: dict) -> dict:
    query = ExposurePathsQuery(**params)
    payload = await asyncio.to_thread(_resolve_exposure_paths_blocking, params=query)
    return payload.model_dump(mode="json")


EXPOSURE_PATHS_READ_MODEL = register_read_model(
    AnalyticalReadModel(
        name="exposure_paths",
        schema_version=1,
        fresh_s=int(getattr(settings, "SEAGULL_EXPOSURE_PATHS_FRESH_SECONDS", 60) or 60),
        stale_s=int(getattr(settings, "SEAGULL_EXPOSURE_PATHS_STALE_SECONDS", 600) or 600),
        key_builder=_exposure_paths_cache_key,
        compute=_compute_exposure_paths,
    )
)


async def list_paths_async(*, params: ExposurePathsQuery) -> tuple[dict, str, str]:
    started = time.perf_counter()
    payload, etag, outcome = await serve_read_model(EXPOSURE_PATHS_READ_MODEL, params.model_dump())
    payload = dict(payload)
    meta = dict(payload.get("meta") or {})
    meta["cache_hit"] = outcome != "miss"
    meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
    payload["meta"] = meta
    observe_hist(
        "api_route_latency_seconds",
        time.perf_counter() - started,
        route="/exposure/paths",
        source=str(meta.get("source") or "compute"),
    )
    return payload, etag, outcome


def list_findings(db: Session, *, params: ExposureFindingsQuery) -> CursorPage[ExposureFindingOut]:
    asset_key = decode_and_validate_asset_key(params.asset_key) if params.asset_key else None
    cursor = parse_cursor_ts_id(params.cursor) if params.cursor else None
    rows = repository.list_findings_page(
        db,
        page_size=params.page_size,
        asset_key=asset_key,
        agent_id=params.agent_id,
        finding_type=params.finding_type,
        severity=params.severity,
        status=params.status,
        q=params.q,
        cursor_parsed=cursor,
    )
    has_more = len(rows) > params.page_size
    items = rows[: params.page_size]
    next_cursor = make_cursor_ts_id(_to_utc(items[-1].last_seen_at) or _utc_now(), int(items[-1].id)) if has_more and items else None
    return CursorPage(items=[_finding_out(row) for row in items], next_cursor=next_cursor, has_more=has_more)


def request_recalculate(db: Session, *, request, admin: PortalPrincipal) -> ExposureRecalculateOut:
    audit_db = db
    requested_at = _utc_now()
    set_offset(_OFFSET_NAME, 0)
    exposure_realtime.request_recalculation(
        requested_at=requested_at,
        requested_by=admin.username,
        request_id=getattr(request.state, "request_id", None),
    )
    write_audit_event(
        audit_db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="exposure.recalculate.request",
        resource_type="exposure",
        resource_id="global",
        outcome="success",
        before={},
        after={"replay_from_event_id": 0, "requested_at": requested_at.isoformat()},
    )
    audit_db.commit()
    return ExposureRecalculateOut(
        accepted=True,
        mode="worker_refresh_requested",
        requested_at=requested_at,
        replay_from_event_id=0,
    )


def open_asset_investigation(
    db: Session,
    *,
    asset_key: str,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> ExposureInvestigationResultOut:
    detail = get_asset_detail(db, asset_key=asset_key)
    posture = detail.posture
    attack_cases = detail.linked_attack_chain_cases
    linked_case_id = attack_cases[0].id if attack_cases else None
    context_key = _exposure_context_key(posture.asset_key, posture.reason_codes, linked_case_id)

    existing = None
    for workspace in repository.list_open_workspaces_for_context(
        db,
        asset_key=asset_key,
        agent_id=posture.agent_id,
        linked_attack_chain_case_id=linked_case_id,
        limit=20,
    ):
        summary = workspace.summary if isinstance(workspace.summary, dict) else {}
        if str(summary.get("exposure_context_key") or "") == context_key:
            existing = workspace
            break

    created = False
    if existing is None:
        workspace = investigations_public.create_workspace(
            db,
            payload=investigations_public.InvestigationWorkspaceCreateIn(
                title=_investigation_title(posture),
                description=_investigation_description(detail),
                severity=posture.severity if posture.severity in {"low", "medium", "high", "critical"} else "medium",
                priority=_priority_from_severity(posture.severity),
                triage_state="triage",
                linked_attack_chain_case_id=linked_case_id,
                primary_agent_id=posture.agent_id,
                initial_note=_investigation_note(detail),
            ),
            request=request,
            user=admin,
            audit_writer=audit_writer,
        )
        created = True
    else:
        workspace = existing

    workspace_id = int(workspace.id)
    if not investigations_public.merge_workspace_summary(
        db,
        workspace_id=workspace_id,
        summary_updates={
            "exposure_asset_key": posture.asset_key,
            "exposure_context_key": context_key,
            "exposure_reason_codes": list(posture.reason_codes[:6]),
        },
        updated_by=admin.username,
    ):
        _raise_api_error(500, "workspace_missing", "Investigation workspace disappeared unexpectedly")

    bookmark_count_added = _sync_exposure_bookmarks(
        db,
        workspace_id=workspace_id,
        asset_detail=detail,
        request=request,
        admin=admin,
        audit_writer=audit_writer,
    )
    investigations_public.refresh_workspace_summary(db, workspace_id=workspace_id, updated_by=admin.username)
    db.commit()
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="exposure.asset.investigation.open",
        resource_type="investigation_workspace",
        resource_id=str(workspace_id),
        outcome="success",
        before={},
        after={
            "workspace_id": workspace_id,
            "workspace_key": workspace.workspace_key,
            "created": created,
            "bookmark_count_added": bookmark_count_added,
        },
        context={"asset_key": asset_key, "agent_id": posture.agent_id},
    )
    db.commit()
    return ExposureInvestigationResultOut(
        created=created,
        workspace_id=workspace_id,
        workspace_key=str(workspace.workspace_key),
        title=str(workspace.title),
        severity=str(workspace.severity),
        priority=str(workspace.priority),
        bookmark_count_added=bookmark_count_added,
    )


def create_asset_triage_response_action(
    db: Session,
    *,
    asset_key: str,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> ExposureTriageResponseActionOut:
    posture = repository.get_asset_posture(db, asset_key)
    if posture is None:
        _raise_api_error(404, "asset_not_found", "Asset posture not found", context={"asset_key": asset_key})
    if not posture.agent_id:
        _raise_api_error(
            409,
            "triage_action_unavailable",
            "A triage response action requires an enrolled agent for this asset",
            context={"asset_key": asset_key},
        )

    payload = response_public.ResponseActionCreateIn(
        action_type="collect_triage_bundle",
        agent_id=str(posture.agent_id),
        payload={
            "collectors": {
                "runtime": True,
                "host": True,
                "processes": True,
                "network": True,
                "auth_log": True,
                "recent_events": True,
                "effective_config": True,
            },
            "limits": {
                "max_auth_log_lines": 500,
                "max_processes": 200,
                "max_connections": 200,
                "max_event_count": 300,
            },
            "redaction": {"mask_secrets": True},
        },
        expires_at=_utc_now() + timedelta(hours=6),
    )
    try:
        action = response_public.create_response_action(
            db,
            payload=payload,
            request=request,
            admin=admin,
            audit_writer=audit_writer,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        if exc.status_code == 422 and "supported" in detail.lower():
            _raise_api_error(
                409,
                "triage_action_unavailable",
                "No safe triage response action is supported in this deployment",
                context={"asset_key": asset_key, "agent_id": posture.agent_id},
            )
        raise
    return ExposureTriageResponseActionOut(
        action_id=int(action.id),
        action_type=str(action.action_type),
        agent_id=str(action.agent_id),
        status=str(action.status),
        requested_at=_to_utc(action.requested_at) or _utc_now(),
        expires_at=_to_utc(action.expires_at),
    )


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


def _posture_out(row: ExposureAssetPostureModel) -> ExposureAssetPostureOut:
    return ExposureAssetPostureOut(
        asset_key=row.asset_key,
        agent_id=row.agent_id,
        asset_type=row.asset_type,
        display_name=row.display_name,
        hostname=row.hostname,
        environment=row.environment,
        criticality=row.criticality,
        severity=normalize_severity(row.severity),
        risk_score=int(row.risk_score or 0),
        confidence=int(row.confidence or 0),
        status=row.status if row.status in {"active", "inactive", "stale", "unknown"} else "unknown",
        first_seen_at=_to_utc(row.first_seen_at) or _utc_now(),
        last_seen_at=_to_utc(row.last_seen_at) or _utc_now(),
        updated_at=_to_utc(row.updated_at) or _utc_now(),
        score_breakdown=_score_breakdown_from_row(row),
        reason_codes=[str(item) for item in list(row.reason_codes or []) if str(item or "").strip()],
        top_recommendations=[_recommendation_out(item) for item in list(row.top_recommendations or [])[:5]],
        evidence_counts={str(key): int(value) for key, value in (row.evidence_counts or {}).items()} if isinstance(row.evidence_counts, dict) else {},
        metadata=_sanitize_json(row.extra_data or {}),
    )


def _finding_out(row: ExposureFindingModel) -> ExposureFindingOut:
    return ExposureFindingOut(
        finding_key=row.finding_key,
        asset_key=row.asset_key,
        agent_id=row.agent_id,
        finding_type=normalize_finding_type(row.finding_type),
        severity=normalize_severity(row.severity),
        score_delta=int(row.score_delta or 0),
        confidence=int(row.confidence or 0),
        title=str(row.title or "")[:256],
        summary=str(row.summary or "")[:1024],
        status=normalize_finding_status(row.status),
        first_seen_at=_to_utc(row.first_seen_at) or _utc_now(),
        last_seen_at=_to_utc(row.last_seen_at) or _utc_now(),
        updated_at=_to_utc(row.updated_at) or _utc_now(),
        related_node_keys=[str(item) for item in list(row.related_node_keys or [])[:24]],
        evidence_refs=[_evidence_ref_out(item) for item in list(row.evidence_refs or [])[:_MAX_PATH_EVIDENCE]],
        reason_codes=[str(item) for item in list(row.reason_codes or [])[:12]],
        recommendations=[_recommendation_out(item) for item in list(row.recommendations or [])[:5]],
        metadata=_sanitize_json(row.extra_data or {}),
    )


def _graph_node_out(row: ExposureNodeModel) -> ExposureGraphNodeOut:
    return ExposureGraphNodeOut(
        node_key=row.node_key,
        node_type=row.node_type,
        asset_key=row.asset_key,
        agent_id=row.agent_id,
        label=str(row.label or "")[:256],
        severity=normalize_severity(row.severity),
        risk_score=int(row.risk_score or 0),
        confidence=int(row.confidence or 0),
        first_seen_at=_to_utc(row.first_seen_at) or _utc_now(),
        last_seen_at=_to_utc(row.last_seen_at) or _utc_now(),
        updated_at=_to_utc(row.updated_at) or _utc_now(),
        properties=_sanitize_json(row.properties or {}),
        source_refs=[_evidence_ref_out(item) for item in list(row.source_refs or [])[:8]],
    )


def _graph_edge_out(row: ExposureEdgeModel) -> ExposureGraphEdgeOut:
    return ExposureGraphEdgeOut(
        edge_key=row.edge_key,
        source_node_key=row.source_node_key,
        target_node_key=row.target_node_key,
        edge_type=row.edge_type,
        asset_key=row.asset_key,
        agent_id=row.agent_id,
        weight=float(row.weight or 0.0),
        confidence=int(row.confidence or 0),
        first_seen_at=_to_utc(row.first_seen_at) or _utc_now(),
        last_seen_at=_to_utc(row.last_seen_at) or _utc_now(),
        updated_at=_to_utc(row.updated_at) or _utc_now(),
        properties=_sanitize_json(row.properties or {}),
        evidence_refs=[_evidence_ref_out(item) for item in list(row.evidence_refs or [])[:8]],
    )


def _score_history_out(row: ExposureScoreHistoryModel) -> ExposureScoreHistoryPointOut:
    breakdown = row.score_breakdown if isinstance(row.score_breakdown, dict) else {}
    return ExposureScoreHistoryPointOut(
        bucket_ts=_to_utc(row.bucket_ts) or _utc_now(),
        risk_score=int(row.risk_score or 0),
        severity=normalize_severity(row.severity),
        confidence=int(row.confidence or 0),
        score_breakdown=ScoreBreakdownOut(
            exposure_score=int(breakdown.get("exposure_score") or 0),
            vulnerability_score=int(breakdown.get("vulnerability_score") or 0),
            active_threat_score=int(breakdown.get("active_threat_score") or 0),
            persistence_score=int(breakdown.get("persistence_score") or 0),
            attack_chain_score=int(breakdown.get("attack_chain_score") or 0),
            asset_criticality_score=int(breakdown.get("asset_criticality_score") or 0),
            reliability_penalty=int(breakdown.get("reliability_penalty") or 0),
        ),
    )


def _recommendation_out(raw: Any) -> RecommendationOut:
    data = dict(raw or {}) if isinstance(raw, dict) else {}
    refs = data.get("related_evidence_refs")
    if not isinstance(refs, list):
        refs = []
    return RecommendationOut(
        action=str(data.get("action") or data.get("rec_type") or "").strip(),
        title=str(data.get("title") or "").strip(),
        reason=str(data.get("reason") or data.get("detail") or "").strip(),
        priority=int(data.get("priority") or 0),
        safety_level=str(data.get("safety_level") or "safe"),
        requires_admin=bool(data.get("requires_admin") or False),
        related_evidence_refs=[_evidence_ref_out(item) for item in refs[:5]],
        reason_code=str(data.get("reason_code") or "").strip() or None,
        metadata=_sanitize_json(data.get("metadata") or {}),
    )


def _evidence_ref_out(raw: Any) -> EvidenceRefOut:
    ref = normalize_evidence_ref(raw if isinstance(raw, dict) else {})
    if ref is None:
        return EvidenceRefOut(
            source_type="event",
            source_id="unknown",
            observed_at=_utc_now(),
            title="",
            summary="",
            metadata={},
        )
    return EvidenceRefOut(
        source_type=ref.source_type,
        source_id=ref.source_id,
        observed_at=_to_utc(ref.observed_at) or _utc_now(),
        title=str(ref.title or "")[:256],
        summary=str(ref.summary or "")[:512],
        metadata=_sanitize_json(ref.metadata or {}),
    )


def _score_breakdown_from_row(row: ExposureAssetPostureModel) -> ScoreBreakdownOut:
    return ScoreBreakdownOut(
        exposure_score=int(row.exposure_score or 0),
        vulnerability_score=int(row.vulnerability_score or 0),
        active_threat_score=int(row.active_threat_score or 0),
        persistence_score=int(row.persistence_score or 0),
        attack_chain_score=int(row.attack_chain_score or 0),
        asset_criticality_score=int(row.asset_criticality_score or 0),
        reliability_penalty=int(row.reliability_penalty or 0),
    )


def _score_breakdown_dataclass(row: ExposureAssetPostureModel):
    from app.features.exposure.domain.types import ScoreBreakdown

    return ScoreBreakdown(
        exposure_score=int(row.exposure_score or 0),
        vulnerability_score=int(row.vulnerability_score or 0),
        active_threat_score=int(row.active_threat_score or 0),
        persistence_score=int(row.persistence_score or 0),
        attack_chain_score=int(row.attack_chain_score or 0),
        asset_criticality_score=int(row.asset_criticality_score or 0),
        reliability_penalty=int(row.reliability_penalty or 0),
    )


def _score_explanation_out(data: dict[str, Any]) -> ScoreExplanationOut:
    return ScoreExplanationOut(**data)


def _alert_out(row) -> ExposureLinkedAlertOut:
    details = row.details if isinstance(row.details, dict) else {}
    metadata = {
        "agent_id": str(details.get("agent_id") or "").strip() or None,
        "rule_id": str(row.rule_id or "").strip(),
    }
    return ExposureLinkedAlertOut(
        id=int(row.id),
        created_at=_to_utc(row.created_at) or _utc_now(),
        rule_id=str(row.rule_id or "")[:64],
        severity=normalize_severity(row.severity),
        confidence=int(row.confidence or 0),
        description=str(row.description or "")[:255],
        src_ip=str(row.src_ip or "").strip() or None,
        dst_ip=str(row.dst_ip or "").strip() or None,
        dst_port=int(row.dst_port) if row.dst_port is not None else None,
        mitre_tactic=str(row.mitre_tactic or "").strip() or None,
        mitre_technique=str(row.mitre_technique or "").strip() or None,
        metadata=_sanitize_json(metadata),
    )


def _vulnerability_out(row) -> ExposureLinkedVulnerabilityOut:
    return ExposureLinkedVulnerabilityOut(
        id=int(row.id),
        fingerprint=str(row.fingerprint or ""),
        cve=str(row.cve or "").strip() or None,
        title=str(row.title or "")[:256],
        severity=normalize_severity(row.severity),
        severity_rank=int(row.severity_rank or 0),
        confidence=int(row.confidence or 0),
        cvss=str(row.cvss or "").strip() or None,
        location=str(row.location or "")[:256] or None,
        description=str(row.description or "")[:1024],
        remediation=str(row.remediation or "")[:1024],
        observation_state=str(row.observation_state or "")[:32],
        operator_disposition=str(row.operator_disposition or "")[:32],
        first_seen_at=_to_utc(row.first_seen_at) or _utc_now(),
        last_seen_at=_to_utc(row.last_seen_at) or _utc_now(),
    )


def _attack_chain_case_out(case, steps: Sequence[Any]) -> ExposureLinkedAttackChainCaseOut:
    return ExposureLinkedAttackChainCaseOut(
        id=int(case.id),
        status=str(case.status or ""),
        score=int(case.score or 0),
        max_stage=str(case.max_stage or "initial_access"),
        step_count=int(case.step_count or 0),
        suspect_ip=str(case.suspect_ip or "").strip() or None,
        first_seen_at=_to_utc(case.first_seen_at) or _utc_now(),
        last_seen_at=_to_utc(case.last_seen_at) or _utc_now(),
        recent_steps=[
            ExposureLinkedAttackChainStepOut(
                id=int(step.id),
                case_id=int(step.case_id),
                stage=str(step.stage or ""),
                label=str(step.label or "")[:96],
                score_delta=int(step.score_delta or 0),
                timestamp=_to_utc(step.timestamp) or _utc_now(),
                event_id=int(step.event_id) if step.event_id is not None else None,
                event_type=str(step.event_type or "").strip() or None,
            )
            for step in list(steps)[:6]
        ],
    )


def _investigation_out(row) -> ExposureLinkedInvestigationOut:
    return ExposureLinkedInvestigationOut(
        id=int(row.id),
        workspace_key=str(row.workspace_key or ""),
        title=str(row.title or "")[:200],
        status=str(row.status or ""),
        severity=str(row.severity or ""),
        priority=str(row.priority or ""),
        assignee=str(row.assignee or "").strip() or None,
        updated_at=_to_utc(row.updated_at) or _utc_now(),
        linked_attack_chain_case_id=int(row.linked_attack_chain_case_id) if row.linked_attack_chain_case_id is not None else None,
        summary=_sanitize_json(row.summary or {}),
    )


def _response_action_out(action, latest_result) -> ExposureLinkedResponseActionOut:
    return ExposureLinkedResponseActionOut(
        id=int(action.id),
        action_type=str(action.action_type or "")[:32],
        status=str(action.status or "")[:24],
        requested_by=str(action.requested_by or "")[:64],
        requested_at=_to_utc(action.requested_at) or _utc_now(),
        expires_at=_to_utc(action.expires_at),
        delivered_at=_to_utc(action.delivered_at),
        started_at=_to_utc(action.started_at),
        finished_at=_to_utc(action.finished_at),
        cancelled_at=_to_utc(action.cancelled_at),
        cancelled_by=str(action.cancelled_by or "").strip() or None,
        last_error=str(action.last_error or "")[:240] or None,
        latest_result_status=str(getattr(latest_result, "status", "") or "").strip() or None,
        payload=_sanitize_json(action.payload or {}),
    )


def _graph_legend() -> ExposureGraphLegendOut:
    node_items = [{"key": key, "label": key.replace("_", " ").title()} for key in sorted(NODE_TYPES)]
    edge_items = [{"key": key, "label": _EDGE_TYPE_LABELS.get(key, key.replace("_", " ").title())} for key in sorted(EDGE_TYPES)]
    return ExposureGraphLegendOut(node_types=node_items, edge_types=edge_items)


def _asset_root_node_key(asset_key: str) -> str:
    from app.features.exposure.domain.normalization import make_node_key

    return make_node_key(NODE_TYPE_ASSET, asset_key)


def _synthetic_asset_node(posture: ExposureAssetPostureModel) -> ExposureNodeModel:
    row = ExposureNodeModel()
    row.node_key = _asset_root_node_key(posture.asset_key)
    row.node_type = "asset"
    row.asset_key = posture.asset_key
    row.agent_id = posture.agent_id
    row.label = posture.display_name
    row.severity = posture.severity
    row.risk_score = posture.risk_score
    row.confidence = posture.confidence
    row.first_seen_at = posture.first_seen_at
    row.last_seen_at = posture.last_seen_at
    row.updated_at = posture.updated_at
    row.properties = {"synthetic": True, "status": posture.status}
    row.source_refs = []
    return row


def _is_attack_path_candidate(row: ExposureAssetPostureModel) -> bool:
    reasons = [str(item) for item in list(row.reason_codes or [])]
    return row.attack_chain_score > 0 or _has_attack_path_reason(reasons)


def _has_attack_path_reason(reason_codes: Sequence[str]) -> bool:
    return any(code in _ATTACK_PATH_REASON_PRIORITY for code in reason_codes)


def _build_attack_path(db: Session, row: ExposureAssetPostureModel) -> ExposureAttackPathOut:
    detail = get_asset_detail(db, asset_key=row.asset_key)
    graph = get_asset_graph(
        db,
        asset_key=row.asset_key,
        params=ExposureGraphQuery(
            depth=3,
            node_types=[],
            edge_types=[],
            min_confidence=20,
            max_nodes=18,
            max_edges=24,
            include_resolved=False,
        ),
    )
    stages = _build_path_stages(detail)
    title = f"Attack path on {detail.posture.display_name}"
    if detail.linked_attack_chain_cases:
        title = f"{detail.linked_attack_chain_cases[0].max_stage.replace('_', ' ').title()} path on {detail.posture.display_name}"
    summary_parts = [reason.replace("_", " ") for reason in detail.reason_codes[:3]]
    summary = f"Prioritized path based on {'; '.join(summary_parts)}." if summary_parts else "Prioritized path based on exposure graph evidence."
    evidence_refs = []
    for finding in detail.top_findings:
        evidence_refs.extend(list(finding.evidence_refs or []))
        if len(evidence_refs) >= _MAX_PATH_EVIDENCE:
            break
    deduped_refs: list[EvidenceRefOut] = []
    seen_ref_keys: set[tuple[str, str]] = set()
    for ref in evidence_refs:
        key = (ref.source_type, ref.source_id)
        if key in seen_ref_keys:
            continue
        seen_ref_keys.add(key)
        deduped_refs.append(ref)
        if len(deduped_refs) >= _MAX_PATH_EVIDENCE:
            break
    return ExposureAttackPathOut(
        path_key=stable_hash(row.asset_key, "|".join(detail.reason_codes[:6]), str(row.updated_at)),
        asset_key=row.asset_key,
        severity=normalize_severity(row.severity),
        risk_score=int(row.risk_score or 0),
        confidence=int(row.confidence or 0),
        title=title,
        summary=summary,
        stages=stages,
        nodes=graph.nodes,
        edges=graph.edges,
        evidence_refs=deduped_refs,
        recommendations=detail.top_recommendations[:3],
    )


def _build_path_stages(detail: ExposureAssetDetailOut) -> list[ExposureAttackPathStageOut]:
    out: list[ExposureAttackPathStageOut] = []
    seen: set[tuple[str, str]] = set()
    for case in detail.linked_attack_chain_cases:
        stage_key = (case.max_stage, "attack_chain")
        if stage_key in seen:
            continue
        seen.add(stage_key)
        out.append(
            ExposureAttackPathStageOut(
                stage=case.max_stage,
                label=f"Attack-chain case {case.id} at {case.max_stage.replace('_', ' ')}",
                source="attack_chain",
                confidence=detail.posture.confidence,
            )
        )
        for step in case.recent_steps[:4]:
            step_key = (step.stage, f"step:{step.id}")
            if step_key in seen:
                continue
            seen.add(step_key)
            out.append(
                ExposureAttackPathStageOut(
                    stage=step.stage,
                    label=step.label,
                    source="attack_chain_step",
                    confidence=detail.posture.confidence,
                )
            )
    for code in detail.reason_codes:
        if code not in _ATTACK_PATH_STAGE_MAP:
            continue
        stage, label = _ATTACK_PATH_STAGE_MAP[code]
        key = (stage, code)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            ExposureAttackPathStageOut(
                stage=stage,
                label=label,
                source=code,
                confidence=detail.posture.confidence,
            )
        )
    return out[:8]


def _parse_assets_cursor(cursor: str, *, expected_sort: str) -> dict[str, Any]:
    from app.core.api.pagination import decode_cursor

    data = decode_cursor(cursor)
    sort = str(data.get("sort") or "").strip().lower()
    if sort != str(expected_sort or "").strip().lower():
        _raise_api_error(400, "invalid_cursor", "cursor does not match the requested sort")
    if sort in {"updated_desc", "last_seen_desc"}:
        field_name = "updated_at" if sort == "updated_desc" else "last_seen_at"
        raw_ts = data.get(field_name)
        if not isinstance(raw_ts, str):
            _raise_api_error(400, "invalid_cursor", "cursor timestamp is invalid")
        try:
            parsed_ts = datetime.fromisoformat(raw_ts)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor") from exc
        return {"id": int(data.get("id") or 0), field_name: _to_utc(parsed_ts) or _utc_now()}
    return {"id": int(data.get("id") or 0), "risk_score": int(data.get("risk_score") or 0)}


def _make_assets_cursor(row: ExposureAssetPostureModel, *, sort: str) -> str:
    normalized = str(sort or "risk_desc").strip().lower()
    if normalized == "updated_desc":
        return encode_cursor({"sort": normalized, "updated_at": (_to_utc(row.updated_at) or _utc_now()).isoformat(), "id": int(row.id)})
    if normalized == "last_seen_desc":
        return encode_cursor({"sort": normalized, "last_seen_at": (_to_utc(row.last_seen_at) or _utc_now()).isoformat(), "id": int(row.id)})
    return encode_cursor({"sort": normalized, "risk_score": int(row.risk_score or 0), "id": int(row.id)})


def _sanitize_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return "<max_depth>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        return text[:512]
    if isinstance(value, list):
        return [_sanitize_json(item, depth=depth + 1) for item in value[:24]]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 32:
                break
            key_text = str(key or "").strip()[:64]
            if not key_text:
                continue
            if any(part in key_text.lower() for part in _SECRET_KEY_PARTS):
                out[key_text] = "<redacted>"
                continue
            out[key_text] = _sanitize_json(item, depth=depth + 1)
        return out
    return str(value)[:256]


def _is_terminal_metadata(metadata: Any) -> bool:
    if not isinstance(metadata, dict):
        return False
    status = str(metadata.get("status") or "").strip().lower()
    return status in _TERMINAL_STATUS


def _posture_changed(before: ExposureAssetPostureModel | None, after: ExposureAssetPostureModel) -> bool:
    if before is None:
        return True
    return any(
        (
            before.risk_score != after.risk_score,
            before.severity != after.severity,
            before.confidence != after.confidence,
            before.status != after.status,
            list(before.reason_codes or []) != list(after.reason_codes or []),
            list(before.top_recommendations or []) != list(after.top_recommendations or []),
        )
    )


def _finding_changed(before: ExposureFindingModel | None, after: ExposureFindingModel) -> bool:
    if before is None:
        return True
    return any(
        (
            before.status != after.status,
            before.severity != after.severity,
            before.score_delta != after.score_delta,
            before.confidence != after.confidence,
            before.title != after.title,
            before.summary != after.summary,
            list(before.reason_codes or []) != list(after.reason_codes or []),
        )
    )


def _priority_from_severity(severity: str) -> str:
    normalized = normalize_severity(severity)
    if normalized == "critical":
        return "p1"
    if normalized == "high":
        return "p2"
    if normalized == "medium":
        return "p3"
    return "p4"


def _investigation_title(posture: ExposureAssetPostureOut) -> str:
    sev = posture.severity.replace("_", " ").title()
    return f"{sev} exposure triage for {posture.display_name}"[:200]


def _investigation_description(detail: ExposureAssetDetailOut) -> str:
    parts = [f"Risk score {detail.posture.risk_score}/{detail.posture.confidence} confidence."]
    if detail.reason_codes:
        parts.append("Reasons: " + ", ".join(detail.reason_codes[:5]) + ".")
    if detail.top_findings:
        titles = [finding.title for finding in detail.top_findings[:3] if finding.title]
        if titles:
            parts.append("Top findings: " + "; ".join(titles) + ".")
    return " ".join(parts)[:4000]


def _investigation_note(detail: ExposureAssetDetailOut) -> str:
    lines = [
        f"Asset: {detail.posture.display_name} ({detail.posture.asset_key})",
        f"Severity: {detail.posture.severity}",
        f"Risk score: {detail.posture.risk_score}",
    ]
    if detail.reason_codes:
        lines.append("Reason codes: " + ", ".join(detail.reason_codes[:6]))
    if detail.top_findings:
        titles = [finding.title for finding in detail.top_findings[:4] if finding.title]
        lines.append("Top findings: " + "; ".join(titles))
    return "\n".join(lines)[:4000]


def _exposure_context_key(asset_key: str, reason_codes: Sequence[str], linked_case_id: int | None) -> str:
    return stable_hash(asset_key, "|".join(sorted(reason_codes[:6])), str(linked_case_id or 0))


def _sync_exposure_bookmarks(
    db: Session,
    *,
    workspace_id: int,
    asset_detail: ExposureAssetDetailOut,
    request,
    admin: PortalPrincipal,
    audit_writer,
) -> int:
    added = 0
    for finding in asset_detail.top_findings[:5]:
        if _create_exposure_bookmark(
            db,
            workspace_id=workspace_id,
            evidence_type="exposure_finding",
            title=finding.title,
            summary=finding.summary,
            agent_id=asset_detail.posture.agent_id,
            observed_at=finding.last_seen_at,
            ref_id=finding.finding_key,
            ref_table="exposure_findings",
            fingerprint=finding.finding_key,
            dedupe_key=stable_hash("exposure_finding", asset_detail.posture.asset_key, finding.finding_key),
            payload_snapshot=_sanitize_json(finding.dict()),
            metadata={"asset_key": asset_detail.posture.asset_key, "reason_codes": list(finding.reason_codes or [])},
            created_by=admin.username,
            request=request,
            admin=admin,
            audit_writer=audit_writer,
        ):
            added += 1
    for alert in asset_detail.linked_alerts[:5]:
        if _create_exposure_bookmark(
            db,
            workspace_id=workspace_id,
            evidence_type="alert",
            title=alert.description,
            summary=f"{alert.rule_id} | {alert.severity}",
            agent_id=asset_detail.posture.agent_id,
            observed_at=alert.created_at,
            ref_id=str(alert.id),
            ref_table="alerts",
            fingerprint=str(alert.id),
            dedupe_key=stable_hash("alert", asset_detail.posture.asset_key, str(alert.id)),
            payload_snapshot=_sanitize_json(alert.dict()),
            metadata={"asset_key": asset_detail.posture.asset_key},
            created_by=admin.username,
            request=request,
            admin=admin,
            audit_writer=audit_writer,
        ):
            added += 1
    for vuln in asset_detail.linked_vulnerabilities[:5]:
        if _create_exposure_bookmark(
            db,
            workspace_id=workspace_id,
            evidence_type="vulnerability",
            title=vuln.title,
            summary=f"{vuln.severity} {vuln.cve or ''}".strip(),
            agent_id=asset_detail.posture.agent_id,
            observed_at=vuln.last_seen_at,
            ref_id=str(vuln.id),
            ref_table="vuln_findings",
            fingerprint=vuln.fingerprint,
            dedupe_key=stable_hash("vulnerability", asset_detail.posture.asset_key, vuln.fingerprint),
            payload_snapshot=_sanitize_json(vuln.dict()),
            metadata={"asset_key": asset_detail.posture.asset_key, "cve": vuln.cve},
            created_by=admin.username,
            request=request,
            admin=admin,
            audit_writer=audit_writer,
        ):
            added += 1
    for attack_case in asset_detail.linked_attack_chain_cases[:3]:
        result = investigations_public.pin_attack_chain_case(
            db,
            workspace_id=workspace_id,
            case_id=attack_case.id,
            payload=investigations_public.InvestigationPinOptionsIn(
                source_module="exposure",
                evidence_subtype="attack_chain",
                note=None,
                tags=["exposure"],
                metadata={"asset_key": asset_detail.posture.asset_key},
            ),
            request=request,
            user=admin,
            audit_writer=audit_writer,
        )
        if result.created:
            added += 1
    return added


def _create_exposure_bookmark(
    db: Session,
    *,
    workspace_id: int,
    evidence_type: str,
    title: str,
    summary: str,
    agent_id: str | None,
    observed_at: datetime | None,
    ref_id: str | None,
    ref_table: str,
    fingerprint: str | None,
    dedupe_key: str,
    payload_snapshot: dict[str, Any],
    metadata: dict[str, Any],
    created_by: str,
    request,
    admin: PortalPrincipal,
    audit_writer,
) -> bool:
    existing = investigations_public.find_bookmark_by_dedupe(db, workspace_id=workspace_id, dedupe_key=dedupe_key)
    if existing is not None:
        return False
    row = investigations_public.create_bookmark(
        db,
        workspace_id=workspace_id,
        evidence_type=evidence_type,
        evidence_subtype="exposure",
        source_module="exposure",
        title=str(title or "")[:200] or evidence_type,
        summary=str(summary or "")[:2000] or None,
        agent_id=agent_id,
        observed_at=_to_utc(observed_at),
        created_by=str(created_by or "analyst")[:64],
        ref_id=ref_id,
        ref_table=ref_table,
        fingerprint=fingerprint,
        dedupe_key=dedupe_key,
        tags=["exposure"],
        payload_snapshot=payload_snapshot,
        metadata=metadata,
    )
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="workspace.bookmark.create",
        resource_type="investigation_bookmark",
        resource_id=str(row.id),
        outcome="success",
        before={},
        after={
            "id": int(row.id),
            "workspace_id": int(workspace_id),
            "evidence_type": evidence_type,
            "ref_id": ref_id,
        },
        context={"source": "exposure", "asset_key": metadata.get("asset_key")},
    )
    return True
