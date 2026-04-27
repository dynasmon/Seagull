"""Exposure Graph worker.

Reads net_events incrementally and runs periodic full posture refreshes.
Projects agent, inventory, vulnerability, alert, attack-chain, and event
signals into the exposure graph tables.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import engine
from app.core.db_lifecycle import ensure_database_ready
from app.core.observability import log_event, setup_logging
from app.features.events.worker_runtime import NetEventModel
from app.features.exposure.realtime import load_recalculation_request
from app.features.exposure import service as exposure_service
from app.features.exposure.domain.evidence import build_evidence_ref, evidence_refs_from_list, merge_evidence_refs
from app.features.exposure.domain.normalization import normalize_asset_key
from app.features.exposure.domain.recommendations import generate_recommendations
from app.features.exposure.domain.scoring import ScoringInputs
from app.features.exposure.worker_runtime import (
    AgentRecord,
    bucket_score_history_ts,
    build_alert_findings,
    build_alert_nodes_and_edges,
    build_asset_node,
    build_attack_chain_findings,
    build_attack_chain_nodes_and_edges,
    build_cve_nodes_and_edges,
    build_event_findings_from_signals,
    build_event_nodes_and_edges,
    build_inventory_service_nodes_and_edges,
    build_investigation_nodes_and_edges,
    build_package_nodes_and_edges,
    build_response_action_nodes_and_edges,
    build_vuln_findings,
    extract_vulnerable_pkg_names,
    load_agent_record,
    load_agents_for_refresh,
    load_alert_signals,
    load_chain_summary,
    load_inventory_data,
    load_investigation_context,
    load_investigation_evidence_refs,
    load_recent_event_rows,
    load_response_action_context,
    load_vuln_signals,
    mark_history_written,
    resolve_inactive_findings,
    should_write_score_history,
    sync_asset_graph,
)
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset

OFFSET_NAME = "exposure_graph_events_v1"
RECALC_REQUEST_KEY = "seagull:exposure:recalc:request"

setup_logging("worker-exposure-graph")
logger = logging.getLogger("seagull.worker.exposure_graph")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _dt_key(dt: datetime | None) -> float:
    safe = _as_utc(dt) or datetime.min.replace(tzinfo=timezone.utc)
    return safe.timestamp()


def _ensure_bootstrap() -> None:
    ensure_database_ready()
    with engine.begin() as conn:
        ensure_offset(OFFSET_NAME, conn=conn)


def _get_last_id() -> int:
    ensure_offset(OFFSET_NAME)
    return get_offset(OFFSET_NAME)


def _set_last_id(last_id: int) -> None:
    set_offset(OFFSET_NAME, last_id)


def _fetch_events(after_id: int, limit: int) -> list[dict[str, Any]]:
    event_types = [
        "ssh_auth",
        "fim_change",
        "persistence_systemd",
        "persistence_cron",
        "ssh_key_change",
        "proc_exec",
        "ebpf_exec",
        "beacon_suspect",
        "c2_suspect",
        "exfil_suspect",
        "egress_anomaly",
    ]
    with engine.begin() as conn:
        rows = conn.execute(
            select(
                NetEventModel.id,
                NetEventModel.agent_id,
                NetEventModel.event_type,
                NetEventModel.timestamp,
                NetEventModel.src_ip,
                NetEventModel.dst_ip,
                NetEventModel.src_port,
                NetEventModel.dst_port,
                NetEventModel.proto,
                NetEventModel.app_proto,
                NetEventModel.dns_qname,
                NetEventModel.http_host,
                NetEventModel.http_method,
                NetEventModel.tls_sni,
                NetEventModel.tls_alpn_first,
                NetEventModel.ja3,
                NetEventModel.ja4,
                NetEventModel.ssh_action,
                NetEventModel.ssh_username,
                NetEventModel.proc_name,
                NetEventModel.proc_exe,
                NetEventModel.proc_parent_name,
                NetEventModel.fim_path,
                NetEventModel.fim_category,
                NetEventModel.heuristic_name,
                NetEventModel.heuristic_confidence,
                NetEventModel.extra,
            )
            .where(NetEventModel.id > int(after_id), NetEventModel.event_type.in_(event_types))
            .order_by(NetEventModel.id.asc())
            .limit(int(limit))
        ).mappings().all()
        return [dict(r) for r in rows]


def _get_max_event_id() -> int:
    with engine.begin() as conn:
        row = conn.execute(select(func.coalesce(func.max(NetEventModel.id), 0))).fetchone()
        try:
            return int(row[0] or 0)
        except Exception:
            return 0


def _order_nodes(nodes: list[Any], *, limit: int) -> list[Any]:
    by_key = {node.node_key: node for node in nodes}
    ordered = sorted(
        by_key.values(),
        key=lambda row: (row.risk_score, row.confidence, _dt_key(row.last_seen_at)),
        reverse=True,
    )
    return ordered[:limit]


def _order_edges(edges: list[Any], *, keep_node_keys: set[str], asset_node_key: str, limit: int) -> list[Any]:
    allowed_keys = set(keep_node_keys)
    allowed_keys.add(asset_node_key)
    by_key = {edge.edge_key: edge for edge in edges}
    ordered = [
        edge for edge in sorted(
            by_key.values(),
            key=lambda row: (row.confidence, row.weight, _dt_key(row.last_seen_at)),
            reverse=True,
        )
        if edge.source_node_key in allowed_keys and edge.target_node_key in allowed_keys
    ]
    return ordered[:limit]


def _prepare_findings(findings: list[Any], *, limit: int) -> list[Any]:
    deduped: dict[str, Any] = {}
    for finding in findings:
        finding.recommendations = [
            rec.to_dict()
            for rec in generate_recommendations(
                finding.reason_codes,
                evidence_refs=[ref.to_dict() for ref in finding.evidence_refs],
            )
        ]
        deduped[finding.finding_key] = finding
    ordered = sorted(
        deduped.values(),
        key=lambda row: (row.score_delta, row.confidence, _dt_key(row.last_seen_at)),
        reverse=True,
    )
    return ordered[:limit]


def _process_event_batch(events: list[dict[str, Any]]) -> tuple[int, dict[str, Any]]:
    if not events:
        return 0, {"fetched": 0, "agents_touched": 0, "agents_refreshed": 0, "errors": 0}

    now = _utc_now()
    last_id = int(events[-1].get("id") or 0)
    agent_events: dict[str, list[dict[str, Any]]] = {}
    latest_seen: dict[str, datetime] = {}
    for ev in events:
        aid = str(ev.get("agent_id") or "").strip()
        if not aid:
            continue
        agent_events.setdefault(aid, []).append(ev)
        ts = ev.get("timestamp")
        if isinstance(ts, datetime):
            latest_seen[aid] = max(ts, latest_seen.get(aid, ts))

    stats = {"fetched": len(events), "agents_touched": len(agent_events), "agents_refreshed": 0, "errors": 0}
    if not agent_events:
        return last_id, stats

    for aid, agent_rows in agent_events.items():
        try:
            with Session(engine) as db:
                agent = load_agent_record(db, agent_id=aid, fallback_last_seen_at=latest_seen.get(aid))
                _refresh_agent_posture(db, agent, now=now, event_rows=agent_rows, resolve_inactive=False)
            stats["agents_refreshed"] += 1
        except Exception as exc:
            stats["errors"] += 1
            log_event(
                logger,
                "warning",
                "exposure_event_refresh_error",
                agent_id=aid,
                error=repr(exc),
            )

    return last_id, stats


def _refresh_agent_posture(
    db: Session,
    agent: AgentRecord,
    *,
    now: datetime,
    event_rows: list[dict[str, Any]] | None = None,
    resolve_inactive: bool = True,
) -> dict[str, Any]:
    aid = agent.agent_id
    lookback_dt = now - timedelta(hours=settings.SEAGULL_EXPOSURE_LOOKBACK_HOURS)
    stale_agent_dt = now - timedelta(minutes=settings.SEAGULL_EXPOSURE_STALE_AGENT_MINUTES)
    stale_inv_dt = now - timedelta(hours=settings.SEAGULL_EXPOSURE_STALE_INVENTORY_HOURS)
    agent_last_seen_at = _as_utc(agent.last_seen_at)
    is_stale_agent = agent_last_seen_at is None or agent_last_seen_at < stale_agent_dt
    inventory = load_inventory_data(db, aid)
    inventory_collected_at = _as_utc(inventory.collected_at if inventory else None)
    is_stale_inventory = inventory is None or inventory_collected_at is None or inventory_collected_at < stale_inv_dt

    hostname = inventory.hostname if inventory else None
    asset_ips = tuple(inventory.ip_addresses) if inventory else ()
    asset_key = normalize_asset_key(aid, ip=None, hostname=hostname, url=None)
    display_name = agent.display_name or aid

    vuln = load_vuln_signals(db, asset_key=asset_key, agent_id=aid, lookback_dt=lookback_dt)
    alerts = load_alert_signals(
        db,
        agent_id=aid,
        lookback_dt=lookback_dt,
        asset_ips=asset_ips,
        hostname=hostname,
        now=now,
    )
    chain = load_chain_summary(db, agent_id=aid)
    investigations = load_investigation_context(db, agent_id=aid)
    investigation_refs = load_investigation_evidence_refs(db, agent_id=aid)
    response_actions = load_response_action_context(db, agent_id=aid)

    open_ports = inventory.open_ports if inventory else []
    packages = inventory.packages if inventory else []
    recent_event_rows = (
        event_rows
        if event_rows is not None
        else load_recent_event_rows(
            db,
            agent_id=aid,
            lookback_dt=lookback_dt,
            limit=max(settings.SEAGULL_EXPOSURE_MAX_GRAPH_EDGES_PER_ASSET * 3, 64),
        )
    )

    asset_node = build_asset_node(
        asset_key,
        agent_id=aid,
        display_name=display_name,
        risk_score=0,
        severity="informational",
        confidence=50,
        now=now,
        first_seen_at=agent_last_seen_at or now,
    )
    max_nodes = settings.SEAGULL_EXPOSURE_MAX_GRAPH_NODES_PER_ASSET
    max_edges = settings.SEAGULL_EXPOSURE_MAX_GRAPH_EDGES_PER_ASSET
    service_nodes, service_edges = build_inventory_service_nodes_and_edges(
        open_ports,
        asset_key=asset_key,
        agent_id=aid,
        asset_node_key=asset_node.node_key,
        now=now,
        max_nodes=min(max_nodes, 16),
    )
    event_nodes, event_edges, event_signals, event_refs = build_event_nodes_and_edges(
        recent_event_rows,
        asset_key=asset_key,
        agent_id=aid,
        asset_node_key=asset_node.node_key,
        now=now,
        max_nodes=min(max_nodes, 64),
        max_edges=min(max_edges, 96),
    )

    posture_refs = merge_evidence_refs([], investigation_refs)
    posture_refs = merge_evidence_refs(posture_refs, event_refs)
    posture_refs = merge_evidence_refs(posture_refs, evidence_refs_from_list(vuln.cve_refs))
    posture_refs = merge_evidence_refs(posture_refs, evidence_refs_from_list(alerts.alert_refs))
    posture_refs = merge_evidence_refs(posture_refs, evidence_refs_from_list(chain.case_refs))
    posture_refs = merge_evidence_refs(
        posture_refs,
        [
            build_evidence_ref(
                source_type="response_action",
                source_id=str(action.action_id),
                observed_at=action.requested_at,
                title=f"Response action: {action.action_type}",
                summary=f"Status: {action.status}, result: {action.result_status or 'n/a'}",
                metadata={"action_type": action.action_type},
            )
            for action in response_actions[:8]
        ],
    )
    if inventory and inventory_collected_at:
        posture_refs = merge_evidence_refs(
            posture_refs,
            [
                build_evidence_ref(
                    source_type="inventory",
                    source_id=aid,
                    observed_at=inventory_collected_at,
                    title=f"Inventory snapshot for {aid}",
                    summary=f"{len(open_ports)} open ports, {inventory.packages_count} packages",
                )
            ],
        )

    scoring_inputs = ScoringInputs(
        asset_key=asset_key,
        agent_id=aid,
        asset_last_seen_at=agent_last_seen_at,
        asset_criticality=agent.criticality,
        critical_vuln_count=vuln.critical_count,
        high_vuln_count=vuln.high_count,
        medium_vuln_count=vuln.medium_count,
        low_vuln_count=vuln.low_count,
        has_exploitability_signal=vuln.has_exploitability_signal,
        active_alert_count=alerts.active_count,
        brute_force_count=alerts.brute_force_count + max(0, event_signals.ssh_fail_count // 5),
        lateral_movement_count=alerts.lateral_movement_count + event_signals.lateral_movement_count,
        suspicious_process_count=alerts.suspicious_process_count + event_signals.suspicious_proc_count,
        sensitive_file_change_count=event_signals.fim_count,
        persistence_signal_count=alerts.persistence_count + event_signals.persistence_count,
        open_attack_chain_count=chain.open_case_count,
        max_attack_chain_score=chain.max_score,
        exposed_service_count=len(open_ports),
        stale_agent=is_stale_agent,
        stale_inventory=is_stale_inventory,
        evidence_refs=posture_refs,
        base_confidence=65,
    )

    first_seen_at = min(dt for dt in [agent_last_seen_at, inventory_collected_at, now] if dt is not None)
    posture_model = exposure_service.compute_and_upsert_posture(
        db,
        asset_key=asset_key,
        agent_id=aid,
        asset_type="host",
        display_name=display_name,
        hostname=hostname,
        environment=None,
        criticality=agent.criticality,
        scoring_inputs=scoring_inputs,
        first_seen_at=first_seen_at,
        last_seen_at=agent_last_seen_at or now,
        evidence_refs=posture_refs,
        metadata={
            "open_port_count": len(open_ports),
            "package_count": len(packages),
            "recent_event_count": len(recent_event_rows),
            "investigation_count": len(investigations),
            "response_action_count": len(response_actions),
        },
    )
    asset_node = build_asset_node(
        asset_key,
        agent_id=aid,
        display_name=display_name,
        risk_score=posture_model.risk_score,
        severity=posture_model.severity,
        confidence=posture_model.confidence,
        now=now,
        first_seen_at=first_seen_at,
    )

    cve_nodes, cve_edges = build_cve_nodes_and_edges(
        db,
        asset_key=asset_key,
        agent_id=aid,
        asset_node_key=asset_node.node_key,
        now=now,
        max_nodes=min(max_nodes, 48),
        lookback_dt=lookback_dt,
    )
    alert_nodes, alert_edges = build_alert_nodes_and_edges(
        db,
        asset_key=asset_key,
        agent_id=aid,
        asset_ips=asset_ips,
        hostname=hostname,
        asset_node_key=asset_node.node_key,
        now=now,
        max_nodes=min(max_nodes, 32),
        lookback_dt=lookback_dt,
    )
    chain_nodes, chain_edges = build_attack_chain_nodes_and_edges(
        db,
        asset_key=asset_key,
        agent_id=aid,
        asset_node_key=asset_node.node_key,
        now=now,
        max_nodes=min(max_nodes, 32),
    )
    vuln_pkg_names = extract_vulnerable_pkg_names(db, asset_key=asset_key, lookback_dt=lookback_dt)
    pkg_nodes, pkg_edges = build_package_nodes_and_edges(
        packages,
        asset_key=asset_key,
        agent_id=aid,
        asset_node_key=asset_node.node_key,
        vulnerable_pkg_names=vuln_pkg_names,
        now=now,
        max_nodes=min(max_nodes, 40),
    )
    inv_nodes, inv_edges = build_investigation_nodes_and_edges(
        investigations,
        asset_key=asset_key,
        agent_id=aid,
        asset_node_key=asset_node.node_key,
        now=now,
    )
    response_nodes, response_edges, _response_refs = build_response_action_nodes_and_edges(
        response_actions,
        asset_key=asset_key,
        agent_id=aid,
        asset_node_key=asset_node.node_key,
        now=now,
    )
    graph_nodes = (
        [asset_node]
        + cve_nodes
        + alert_nodes
        + chain_nodes
        + pkg_nodes
        + inv_nodes
        + response_nodes
        + service_nodes
        + event_nodes
    )
    ordered_nodes = [asset_node] + _order_nodes(
        [node for node in graph_nodes if node.node_key != asset_node.node_key],
        limit=max_nodes - 1,
    )
    keep_node_keys = {node.node_key for node in ordered_nodes}
    graph_edges = (
        cve_edges
        + alert_edges
        + chain_edges
        + pkg_edges
        + inv_edges
        + response_edges
        + service_edges
        + event_edges
    )
    ordered_edges = _order_edges(
        graph_edges,
        keep_node_keys=keep_node_keys,
        asset_node_key=asset_node.node_key,
        limit=max_edges,
    )
    keep_edge_keys = {edge.edge_key for edge in ordered_edges}
    for node in ordered_nodes:
        exposure_service.upsert_node(db, node)
    for edge in ordered_edges:
        exposure_service.upsert_edge(db, edge)
    sync_asset_graph(db, asset_key=asset_key, keep_node_keys=keep_node_keys, keep_edge_keys=keep_edge_keys)

    max_findings = settings.SEAGULL_EXPOSURE_MAX_FINDINGS_PER_ASSET
    vuln_findings = build_vuln_findings(
        db,
        asset_key=asset_key,
        agent_id=aid,
        lookback_dt=lookback_dt,
        max_findings=max_findings,
        now=now,
    )
    alert_findings = build_alert_findings(
        db,
        asset_key=asset_key,
        agent_id=aid,
        asset_ips=asset_ips,
        hostname=hostname,
        lookback_dt=lookback_dt,
        max_findings=max_findings,
        now=now,
    )
    chain_findings = build_attack_chain_findings(
        db,
        asset_key=asset_key,
        agent_id=aid,
        max_findings=max_findings,
        now=now,
    )
    event_findings = build_event_findings_from_signals(event_signals, asset_key=asset_key, now=now)
    selected_findings = _prepare_findings(
        vuln_findings + alert_findings + chain_findings + event_findings,
        limit=max_findings,
    )
    for finding in selected_findings:
        exposure_service.upsert_finding(db, finding)
    if resolve_inactive:
        resolve_inactive_findings(
            db,
            asset_key=asset_key,
            active_finding_keys={finding.finding_key for finding in selected_findings},
            now=now,
        )

    min_interval = settings.SEAGULL_EXPOSURE_SCORE_HISTORY_EVERY_SECONDS
    history_bucket = bucket_score_history_ts(now, min_interval)
    if should_write_score_history(db, asset_key=asset_key, now=history_bucket, min_interval_seconds=min_interval):
        exposure_service.record_score_history(
            db,
            asset_key=asset_key,
            agent_id=aid,
            bucket_ts=history_bucket,
            risk_score=posture_model.risk_score,
            severity=posture_model.severity,
            confidence=posture_model.confidence,
            score_breakdown=posture_model.score_breakdown or {},
        )
        mark_history_written(asset_key, history_bucket)

    db.commit()

    return {
        "nodes": len(ordered_nodes),
        "edges": len(ordered_edges),
        "findings": len(selected_findings),
        "risk_score": posture_model.risk_score,
        "severity": posture_model.severity,
    }


def _run_posture_refresh() -> dict[str, Any]:
    now = _utc_now()
    batch_limit = max(1, settings.SEAGULL_EXPOSURE_EVENT_BATCH_SIZE)
    agents_refreshed = 0
    errors = 0

    with Session(engine) as db:
        agents = load_agents_for_refresh(db, limit=batch_limit)

    for agent in agents:
        try:
            with Session(engine) as db:
                _refresh_agent_posture(db, agent, now=now)
            agents_refreshed += 1
        except Exception as e:
            errors += 1
            log_event(
                logger,
                "warning",
                "exposure_posture_refresh_error",
                agent_id=agent.agent_id,
                error=repr(e),
            )

    return {"agents_refreshed": agents_refreshed, "errors": errors}


def main() -> None:
    settings.validate_for_service("worker-exposure-graph")
    if not settings.SEAGULL_EXPOSURE_ENABLED:
        log_event(logger, "info", "exposure_graph_disabled")
        return

    _ensure_bootstrap()

    every = float(settings.SEAGULL_EXPOSURE_EVERY_SECONDS)
    batch_size = int(settings.SEAGULL_EXPOSURE_EVENT_BATCH_SIZE)

    log_event(
        logger,
        "info",
        "exposure_graph_start",
        every_s=every,
        batch_size=batch_size,
        lookback_hours=settings.SEAGULL_EXPOSURE_LOOKBACK_HOURS,
        stale_agent_minutes=settings.SEAGULL_EXPOSURE_STALE_AGENT_MINUTES,
        stale_inventory_hours=settings.SEAGULL_EXPOSURE_STALE_INVENTORY_HOURS,
    )

    backoff = 1.0
    last_id = 0
    last_refresh_t = 0.0
    last_idle_log_t = 0.0
    last_recalc_token = ""
    idle_sleep = 5.0

    while True:
        try:
            if last_id == 0:
                last_id = _get_last_id()

            recalc_request = load_recalculation_request(RECALC_REQUEST_KEY)
            recalc_token = str((recalc_request or {}).get("requested_at") or "")
            if recalc_token and recalc_token != last_recalc_token:
                last_recalc_token = recalc_token
                last_refresh_t = 0.0
                log_event(
                    logger,
                    "info",
                    "exposure_graph_recalc_requested",
                    requested_at=recalc_request.get("requested_at"),
                    requested_by=recalc_request.get("requested_by"),
                    mode=recalc_request.get("mode"),
                )

            # Incremental event processing
            events = _fetch_events(last_id, batch_size)
            if events:
                t0 = time.time()
                new_last, ev_stats = _process_event_batch(events)
                if new_last and new_last > last_id:
                    last_id = new_last
                    _set_last_id(last_id)
                took_ms = int((time.time() - t0) * 1000)
                log_event(
                    logger,
                    "info",
                    "exposure_graph_events_ok",
                    last_id=last_id,
                    took_ms=took_ms,
                    **ev_stats,
                )
                backoff = 1.0
            else:
                now_t = time.time()
                if (now_t - last_idle_log_t) >= 30.0:
                    max_id = _get_max_event_id()
                    lag = max(0, int(max_id) - int(last_id))
                    log_event(
                        logger,
                        "info",
                        "exposure_graph_idle",
                        last_id=last_id,
                        max_id=max_id,
                        lag=lag,
                    )
                    last_idle_log_t = now_t

            # Periodic full posture refresh
            now_t = time.time()
            if every > 0 and (now_t - last_refresh_t) >= every:
                t0 = time.time()
                refresh_stats = _run_posture_refresh()
                took_ms = int((time.time() - t0) * 1000)
                last_refresh_t = time.time()
                log_event(
                    logger,
                    "info",
                    "exposure_graph_refresh_ok",
                    took_ms=took_ms,
                    **refresh_stats,
                )
                backoff = 1.0

            time.sleep(idle_sleep)

        except KeyboardInterrupt:
            raise
        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "exposure_graph_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "exposure_graph_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
