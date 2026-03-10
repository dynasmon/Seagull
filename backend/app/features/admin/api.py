from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, case, func, select, text

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.es import get_es_client, search_backend_mode
from app.core.ingest_control import get_storm_status
from app.core.observability import snapshot_metrics
from app.core.portal_auth import PortalPrincipal, require_admin
from app.core.redis_client import get_redis
from app.models.agents import AgentModel
from app.models.inventory import AgentInventorySnapshotModel
from app.models.portal_login_events import PortalLoginEventModel
from app.models.portal_users import PortalUserModel
from app.schemas.admin import LoginEventOut, RuntimeConfigOut


router = APIRouter(prefix="/admin", tags=["admin"])
_STARTED_AT_MONO = time.monotonic()


@router.get("/runtime-config", response_model=RuntimeConfigOut)
def admin_runtime_config(_: PortalPrincipal = Depends(require_admin)):
    return {"config": settings.runtime_config_for_admin()}


@router.get("/login-history", response_model=list[LoginEventOut])
def admin_login_history(
    limit: int = Query(20, ge=1, le=100),
    include_failed: bool = Query(False),
    admin: PortalPrincipal = Depends(require_admin),
):
    """Return recent login events for admin accounts.

    Only admins can call this endpoint.
    """
    db = SessionLocal()
    try:
        q = (
            db.query(PortalLoginEventModel)
            .join(PortalUserModel, PortalUserModel.username == PortalLoginEventModel.username)
            .filter(PortalUserModel.role == "admin")
            .order_by(PortalLoginEventModel.created_at.desc())
        )
        if not include_failed:
            q = q.filter(PortalLoginEventModel.succeeded.is_(True))
        rows = q.limit(limit).all()

        out: list[LoginEventOut] = []
        for r in rows:
            out.append(
                {
                    "created_at": r.created_at,
                    "username": r.username or "",
                    "method": r.method,
                    "ip": r.ip,
                    "user_agent": r.user_agent,
                    "succeeded": bool(r.succeeded),
                }
            )
        return out
    finally:
        db.close()


@router.get("/system-status")
def admin_system_status(_: PortalPrincipal = Depends(require_admin)):
    now = datetime.now(timezone.utc)
    online_cutoff = datetime.utcnow() - timedelta(minutes=5)
    inventory_stale_cutoff = now - timedelta(minutes=30)

    db = SessionLocal()
    try:
        api_health = {"status": "ok", "latency_ms": None, "error": None}
        db_health = {"status": "degraded", "latency_ms": None, "error": None}
        t0 = time.perf_counter()
        try:
            db.execute(text("SELECT 1"))
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

        total_agents = int(db.execute(select(func.count()).select_from(AgentModel)).scalar() or 0)
        online_agents = int(
            db.execute(
                select(func.count()).select_from(AgentModel).where(
                    and_(AgentModel.is_revoked.is_(False), AgentModel.last_seen_at.is_not(None), AgentModel.last_seen_at >= online_cutoff)
                )
            ).scalar()
            or 0
        )
        revoked_agents = int(
            db.execute(select(func.count()).select_from(AgentModel).where(AgentModel.is_revoked.is_(True))).scalar() or 0
        )
        offline_agents = int(max(total_agents - online_agents - revoked_agents, 0))

        inv_rn = func.row_number().over(
            partition_by=AgentInventorySnapshotModel.agent_id,
            order_by=AgentInventorySnapshotModel.collected_at.desc(),
        )
        latest_inv = (
            select(
                AgentInventorySnapshotModel.agent_id.label("agent_id"),
                AgentInventorySnapshotModel.collected_at.label("collected_at"),
                inv_rn.label("rn"),
            )
            .subquery()
        )
        latest_only = select(latest_inv).where(latest_inv.c.rn == 1).subquery()
        inv_counts = db.execute(
            select(
                func.sum(case((latest_only.c.collected_at.is_(None), 1), else_=0)).label("no_inventory"),
                func.sum(
                    case(
                        (
                            and_(
                                latest_only.c.collected_at.is_not(None),
                                latest_only.c.collected_at < inventory_stale_cutoff,
                            ),
                            1,
                        ),
                        else_=0,
                    )
                ).label("stale"),
                func.sum(case((latest_only.c.collected_at >= inventory_stale_cutoff, 1), else_=0)).label("fresh"),
            )
            .select_from(AgentModel)
            .outerjoin(latest_only, AgentModel.agent_id == latest_only.c.agent_id)
        ).mappings().first()

        inv_no = int((inv_counts or {}).get("no_inventory") or 0)
        inv_stale = int((inv_counts or {}).get("stale") or 0)
        inv_fresh = int((inv_counts or {}).get("fresh") or 0)

        t_ing = time.perf_counter()
        storm = get_storm_status()
        ingest_latency_ms = round((time.perf_counter() - t_ing) * 1000.0, 2)
        pressure_status = "ok"
        if bool(storm.get("active")):
            pressure_status = "storm" if (storm.get("phase") == "storm") else "degraded"

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

        # Best-effort API latency from in-process request histograms.
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
                "environment": settings.NETWATCH_ENV,
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
                    "url": settings.NETWATCH_ES_URL,
                    "available": bool(es_ok),
                    "error": es_error,
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
    finally:
        db.close()
