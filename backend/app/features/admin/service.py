from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.audit import AuditActor, write_audit_event
from app.core.cache import get_redis
from app.core.config import settings
from app.core.integrations.clickhouse import clickhouse_is_available, clickhouse_is_enabled, get_clickhouse_client
from app.core.integrations.es import get_es_client, search_backend_mode
from app.core.observability import snapshot_metrics
from app.features.admin import repository
from app.features.admin.schemas import AdminAuditEventOut, AdminAuditQueryOut, LoginEventOut
from app.features.ingest.control.service import get_storm_status

_STARTED_AT_MONO = time.monotonic()


def record_audit(
    db: Session,
    *,
    request,
    actor: AuditActor,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str = "success",
    before: dict | None = None,
    after: dict | None = None,
    context: dict | None = None,
    reason: str | None = None,
    error: str | None = None,
    event_type: str = "admin_action",
) -> None:
    write_audit_event(
        db,
        request=request,
        actor=actor,
        event_type=event_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        before=(before or {}),
        after=(after or {}),
        context=(context or {}),
        reason=reason,
        error=error,
    )


def admin_audit_events(
    db: Session,
    *,
    limit: int,
    event_type: str | None,
    action: str | None,
    outcome: str | None,
    resource_type: str | None,
    actor_username: str | None,
    since: datetime | None,
    until: datetime | None,
) -> AdminAuditQueryOut:
    rows = repository.list_audit_events(
        db,
        limit=limit,
        event_type=event_type,
        action=action,
        outcome=outcome,
        resource_type=resource_type,
        actor_username=actor_username,
        since=since,
        until=until,
    )
    has_more = len(rows) > limit
    items: list[AdminAuditEventOut] = []
    for r in rows[:limit]:
        items.append(
            AdminAuditEventOut(
                id=r.id,
                operation_id=r.operation_id,
                created_at=r.created_at,
                event_type=r.event_type,
                action=r.action,
                outcome=r.outcome,
                actor_user_id=r.actor_user_id,
                actor_username=r.actor_username,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                request_id=r.request_id,
                trace_id=r.trace_id,
                ip=r.ip,
                user_agent=r.user_agent,
                method=r.method,
                path=r.path,
                reason=r.reason,
                error=r.error,
                changed_fields=[str(x) for x in (r.changed_fields or [])],
                before=r.before if isinstance(r.before, dict) else {},
                after=r.after if isinstance(r.after, dict) else {},
                context=r.context if isinstance(r.context, dict) else {},
                prev_event_hash=r.prev_event_hash,
                event_hash=r.event_hash,
            )
        )
    return AdminAuditQueryOut(items=items, has_more=has_more)


def admin_runtime_config() -> dict:
    return {"config": settings.runtime_config_for_admin()}


def admin_login_history(db: Session, *, limit: int, include_failed: bool) -> list[LoginEventOut]:
    rows = repository.list_admin_login_events(db, limit=limit, include_failed=include_failed)
    out: list[LoginEventOut] = []
    for r in rows:
        out.append(
            LoginEventOut(
                created_at=r.created_at,
                username=r.username or "",
                method=r.method,
                ip=r.ip,
                user_agent=r.user_agent,
                succeeded=bool(r.succeeded),
            )
        )
    return out


def admin_system_status(db: Session) -> dict:
    now = datetime.now(timezone.utc)
    online_cutoff = datetime.utcnow() - timedelta(minutes=5)
    inventory_stale_cutoff = now - timedelta(minutes=30)

    api_health = {"status": "ok", "latency_ms": None, "error": None}
    db_health = {"status": "degraded", "latency_ms": None, "error": None}
    t0 = time.perf_counter()
    try:
        repository.probe_database(db)
        db_health["status"] = "ok"
        db_health["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
    except Exception as e:
        db_health["error"] = str(e).splitlines()[0][:200]

    redis_health = {"status": "degraded", "latency_ms": None, "error": None}
    try:
        r = get_redis()
        if r is None:
            redis_health["error"] = "redis unavailable"
        else:
            t1 = time.perf_counter()
            ok = bool(r.ping())
            redis_health["latency_ms"] = round((time.perf_counter() - t1) * 1000.0, 2)
            redis_health["status"] = "ok" if ok else "degraded"
            if not ok:
                redis_health["error"] = "ping failed"
    except Exception as e:
        redis_health["error"] = str(e).splitlines()[0][:200]

    es_mode = search_backend_mode()
    es_ok = False
    es_latency_ms = None
    es_error = None
    try:
        t_es = time.perf_counter()
        es_ok = bool(get_es_client().ping())
        es_latency_ms = round((time.perf_counter() - t_es) * 1000.0, 2)
    except Exception as e:
        es_error = str(e).splitlines()[0][:200]
    es_required = es_mode == "elasticsearch"
    es_status = "ok" if es_ok else ("down" if es_required else "degraded")

    ch_enabled = bool(clickhouse_is_enabled())
    ch_ok = False
    ch_latency_ms = None
    ch_error = None
    if ch_enabled:
        try:
            t_ch = time.perf_counter()
            ch_ok = bool(clickhouse_is_available())
            if ch_ok:
                row = get_clickhouse_client().query("SELECT 1").first_row
                ch_ok = bool(row and int(row[0]) == 1)
            ch_latency_ms = round((time.perf_counter() - t_ch) * 1000.0, 2)
        except Exception as e:
            ch_error = str(e).splitlines()[0][:200]
            ch_ok = False
    ch_status = "ok" if ch_ok else ("down" if ch_enabled else "degraded")

    total_agents = repository.count_total_agents(db)
    online_agents = repository.count_online_agents(db, online_cutoff=online_cutoff)
    revoked_agents = repository.count_revoked_agents(db)
    offline_agents = int(max(total_agents - online_agents - revoked_agents, 0))

    inv_no, inv_stale, inv_fresh = repository.inventory_status_counts(db, inventory_stale_cutoff=inventory_stale_cutoff)

    t_ing = time.perf_counter()
    storm = get_storm_status()
    ingest_latency_ms = round((time.perf_counter() - t_ing) * 1000.0, 2)
    pressure_status = "ok"
    if bool(storm.get("active")):
        pressure_status = "storm" if (storm.get("phase") in {"storm", "shedding"}) else "degraded"

    metrics = snapshot_metrics()
    counters = metrics.get("counters") or []
    histograms = metrics.get("histograms") or []
    http_total = 0.0
    for row in counters:
        if row.get("name") == "http_requests_total":
            try:
                http_total += float(row.get("value") or 0.0)
            except Exception:
                pass

    api_latency_sum = 0.0
    api_latency_count = 0.0
    for row in histograms:
        if row.get("name") != "http_request_duration_ms":
            continue
        try:
            api_latency_sum += float(row.get("sum") or 0.0)
            api_latency_count += float(row.get("count") or 0.0)
        except Exception:
            pass
    if api_latency_count > 0:
        api_health["latency_ms"] = round(api_latency_sum / api_latency_count, 2)

    return {
        "service": {
            "name": "backend-api",
            "environment": settings.SEAGULL_ENV,
            "version": "0.1.0",
            "now_utc": now.isoformat(),
            "uptime_seconds": int(max(time.monotonic() - _STARTED_AT_MONO, 0)),
        },
        "components": {
            "api": api_health,
            "database": db_health,
            "redis": redis_health,
            "elasticsearch": {
                "status": es_status,
                "latency_ms": es_latency_ms,
                "mode": es_mode,
                "url": settings.SEAGULL_ES_URL,
                "available": bool(es_ok),
                "error": es_error,
            },
            "clickhouse": {
                "status": ch_status,
                "latency_ms": ch_latency_ms,
                "enabled": ch_enabled,
                "available": bool(ch_ok),
                "error": ch_error,
            },
            "ingest_pressure": {
                "status": pressure_status,
                "latency_ms": ingest_latency_ms,
                "storm": storm,
            },
        },
        "fleet": {
            "total_agents": total_agents,
            "online_agents": online_agents,
            "offline_agents": offline_agents,
            "revoked_agents": revoked_agents,
            "inventory": {
                "fresh": inv_fresh,
                "stale": inv_stale,
                "no_inventory": inv_no,
            },
        },
        "observability": {
            "counters_total": len(counters),
            "histograms_total": len(histograms),
            "http_requests_total": round(http_total, 2),
        },
    }
