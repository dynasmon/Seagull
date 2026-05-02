from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import engine
from app.core.observability import log_event
from app.features.events.worker_runtime import NetEventModel
from app.features.exposure.worker_runtime import load_agent_record

from .ordering import _utc_now
from .posture import _refresh_agent_posture

logger = logging.getLogger("seagull.worker.exposure_graph")


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
