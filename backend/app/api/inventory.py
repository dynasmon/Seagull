import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, text

from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.portal_auth import get_current_user
from app.core.db import SessionLocal
from app.models.inventory import AgentInventorySnapshotModel
from app.schemas.inventory import InventorySnapshotIn, InventorySnapshotOut, PackageEntry


router = APIRouter(
    prefix="/inventory",
    tags=["inventory"],
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_packages(packages: List[PackageEntry]) -> bytes:
    rows = [f"{p.name}\t{p.version}\t{p.arch or ''}" for p in packages]
    rows.sort()
    return ("\n".join(rows) + "\n").encode("utf-8") if rows else b""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_hhmm(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%H:%M")


def _floor_dt(dt: datetime, minutes_step: int) -> datetime:
    """Floor dt to the closest lower multiple of minutes_step (UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    minute = (dt.minute // minutes_step) * minutes_step
    return dt.replace(minute=minute, second=0, microsecond=0)


@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_inventory(
    payload: InventorySnapshotIn,
    agent: AgentPrincipal = Depends(get_current_agent),
):
    now = _utc_now()

    packages_count = payload.packages_count if payload.packages_count is not None else len(payload.packages)
    if packages_count != len(payload.packages):
        packages_count = len(payload.packages)

    packages_hash = (payload.packages_hash or "").strip()
    if not packages_hash or len(packages_hash) != 64:
        packages_hash = _sha256_hex(_canonical_packages(payload.packages))

    extra = dict(payload.extra or {})
    if payload.collected_at is not None:
        try:
            ts = payload.collected_at
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            extra.setdefault("client_collected_at", ts.isoformat())
        except Exception:
            pass

    db = SessionLocal()
    try:
        row = AgentInventorySnapshotModel(
            agent_id=agent.agent_id,
            collected_at=now,
            schema_version=int(payload.schema_version or 1),
            os=dict(payload.os or {}),
            packages=[p.dict() for p in payload.packages],
            packages_hash=packages_hash,
            packages_count=int(packages_count),
            manager=payload.manager,
            extra=extra,
        )
        db.add(row)
        db.commit()
        return {"id": row.id, "stored": True}
    finally:
        db.close()


@router.get("/me/latest", response_model=InventorySnapshotOut)
async def get_my_latest_inventory(agent: AgentPrincipal = Depends(get_current_agent)):
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent.agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(1)
        )
        row = db.execute(stmt).scalars().first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No inventory")
        return row
    finally:
        db.close()


@router.get("/me/history", response_model=List[InventorySnapshotOut])
async def get_my_inventory_history(
    limit: int = Query(20, ge=1, le=200),
    agent: AgentPrincipal = Depends(get_current_agent),
):
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent.agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(limit)
        )
        return db.execute(stmt).scalars().all()
    finally:
        db.close()


@router.get("/{agent_id}/latest", response_model=InventorySnapshotOut)
async def get_agent_latest_inventory(agent_id: str, _user=Depends(get_current_user)):
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(1)
        )
        row = db.execute(stmt).scalars().first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No inventory")
        return row
    finally:
        db.close()


@router.get("/{agent_id}/history", response_model=List[InventorySnapshotOut])
async def get_agent_inventory_history(
    agent_id: str,
    limit: int = Query(20, ge=1, le=200),
    _user=Depends(get_current_user),
):
    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(limit)
        )
        return db.execute(stmt).scalars().all()
    finally:
        db.close()


@router.get("/overview")
async def get_inventory_overview(
    window_minutes: int = Query(360, ge=30, le=7 * 24 * 60, description="Time window (minutes) for inventory charts"),
    agent_id: Optional[str] = Query(None, description="Optional agent filter. Use '__all' or omit for all agents."),
    _user=Depends(get_current_user),
):
    """Aggregated snapshot for the Inventory page (Grafana-like).

    Mirrors the key panels from infra/grafana/provisioning/dashboards/netwatch-endpoint-sprint1.json
    while keeping the portal client simple (minimal client-side aggregation).
    """

    a = (agent_id or "").strip()
    if not a or a == "__all":
        a = None

    now = _utc_now()
    start_ts = now - timedelta(minutes=window_minutes)

    # Align bucket starts to match Grafana grouping behavior.
    start_1m = _floor_dt(start_ts, 1)
    start_10m = _floor_dt(start_ts, 10)
    end_1m = _floor_dt(now, 1)
    end_10m = _floor_dt(now, 10)

    db = SessionLocal()
    try:
        params = {"start_ts": start_ts, "end_ts": now, "agent_id": a, "start_1m": start_1m, "end_1m": end_1m, "start_10m": start_10m, "end_10m": end_10m}

        # -----------------------------
        # KPIs
        # -----------------------------
        q_kpis = text(
            """
            WITH last AS (
              SELECT agent_id, MAX(collected_at) AS last_at
              FROM agent_inventory_snapshots
              GROUP BY agent_id
            )
            SELECT
              (SELECT COUNT(*)::int FROM agents) AS agents_total,

              (SELECT COUNT(*)::int
               FROM agents
               WHERE last_seen_at >= (now() AT TIME ZONE 'utc') - interval '5 minutes'
                 AND (:agent_id IS NULL OR agent_id = :agent_id)
              ) AS agents_online_5m,

              (SELECT COUNT(DISTINCT agent_id)::int
               FROM agent_inventory_snapshots
               WHERE collected_at >= (now() AT TIME ZONE 'utc') - interval '6 hours'
                 AND (:agent_id IS NULL OR agent_id = :agent_id)
              ) AS agents_with_inventory_6h,

              (SELECT COALESCE(MAX(EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'utc') - last_at)) / 60), 0)::int
               FROM last
               WHERE (:agent_id IS NULL OR agent_id = :agent_id)
              ) AS oldest_inventory_age_minutes;
            """
        )
        k = db.execute(q_kpis, {"agent_id": a}).mappings().first() or {}
        kpis = {
            "agents_total": int(k.get("agents_total") or 0),
            "agents_online_5m": int(k.get("agents_online_5m") or 0),
            "agents_with_inventory_6h": int(k.get("agents_with_inventory_6h") or 0),
            "oldest_inventory_age_minutes": int(k.get("oldest_inventory_age_minutes") or 0),
        }

        # -----------------------------
        # Inventory snapshots per minute
        # -----------------------------
        q_snap = text(
            """
            WITH buckets AS (
              SELECT generate_series(
                date_trunc('minute', :start_1m),
                date_trunc('minute', :end_1m),
                interval '1 minute'
              ) AS bucket_ts
            ),
            agg AS (
              SELECT date_trunc('minute', collected_at) AS bucket_ts,
                     COUNT(*)::bigint AS value
              FROM agent_inventory_snapshots
              WHERE collected_at >= :start_ts
                AND collected_at <= :end_ts
                AND (:agent_id IS NULL OR agent_id = :agent_id)
              GROUP BY 1
            )
            SELECT b.bucket_ts, COALESCE(a.value, 0)::bigint AS value
            FROM buckets b
            LEFT JOIN agg a ON a.bucket_ts = b.bucket_ts
            ORDER BY b.bucket_ts ASC;
            """
        )
        snap_rows = db.execute(q_snap, params).mappings().all()
        snapshots_per_minute = {
            "series": ["value"],
            "data": [{"t": _fmt_hhmm(r["bucket_ts"]), "value": int(r.get("value") or 0)} for r in snap_rows],
        }

        # -----------------------------
        # Inventory changes per 10m (packages hash)
        # -----------------------------
        q_changes = text(
            """
            WITH buckets AS (
              SELECT generate_series(
                date_trunc('minute', :start_10m),
                date_trunc('minute', :end_10m),
                interval '10 minutes'
              ) AS bucket_ts
            ),
            s AS (
              SELECT
                agent_id,
                collected_at,
                packages_hash,
                LAG(packages_hash) OVER (PARTITION BY agent_id ORDER BY collected_at) AS prev_hash
              FROM agent_inventory_snapshots
              WHERE collected_at >= :start_ts
                AND collected_at <= :end_ts
                AND (:agent_id IS NULL OR agent_id = :agent_id)
            ),
            agg AS (
              SELECT
                (date_trunc('hour', collected_at) + (floor(extract(minute from collected_at) / 10) * interval '10 minutes')) AS bucket_ts,
                COUNT(*)::bigint AS value
              FROM s
              WHERE prev_hash IS DISTINCT FROM packages_hash
              GROUP BY 1
            )
            SELECT b.bucket_ts, COALESCE(a.value, 0)::bigint AS value
            FROM buckets b
            LEFT JOIN agg a ON a.bucket_ts = b.bucket_ts
            ORDER BY b.bucket_ts ASC;
            """
        )
        ch_rows = db.execute(q_changes, params).mappings().all()
        changes_per_10m = {
            "series": ["value"],
            "data": [{"t": _fmt_hhmm(r["bucket_ts"]), "value": int(r.get("value") or 0)} for r in ch_rows],
        }

        # -----------------------------
        # OS distribution (latest snapshot per agent within window)
        # -----------------------------
        q_os = text(
            """
            WITH latest AS (
              SELECT DISTINCT ON (agent_id) agent_id, os
              FROM agent_inventory_snapshots
              WHERE collected_at >= :start_ts
                AND collected_at <= :end_ts
                AND (:agent_id IS NULL OR agent_id = :agent_id)
              ORDER BY agent_id, collected_at DESC
            )
            SELECT
              COALESCE(NULLIF(os->>'pretty_name',''), NULLIF(os->>'name',''), os->>'id', os->>'goos', 'unknown') AS os,
              COUNT(*)::bigint AS agents
            FROM latest
            GROUP BY 1
            ORDER BY agents DESC, os ASC;
            """
        )
        os_rows = db.execute(q_os, params).mappings().all()
        os_distribution = [{"os": str(r.get("os") or "unknown"), "agents": int(r.get("agents") or 0)} for r in os_rows]

        # -----------------------------
        # Package manager distribution (latest snapshot per agent within window)
        # -----------------------------
        q_mgr = text(
            """
            WITH latest AS (
              SELECT DISTINCT ON (agent_id) agent_id, manager
              FROM agent_inventory_snapshots
              WHERE collected_at >= :start_ts
                AND collected_at <= :end_ts
                AND (:agent_id IS NULL OR agent_id = :agent_id)
              ORDER BY agent_id, collected_at DESC
            )
            SELECT COALESCE(NULLIF(manager,''), 'unknown') AS manager,
                   COUNT(*)::bigint AS agents
            FROM latest
            GROUP BY 1
            ORDER BY agents DESC, manager ASC;
            """
        )
        mgr_rows = db.execute(q_mgr, params).mappings().all()
        manager_distribution = [{"manager": str(r.get("manager") or "unknown"), "agents": int(r.get("agents") or 0)} for r in mgr_rows]

        # -----------------------------
        # Inventory age by agent (minutes) - top 50
        # -----------------------------
        q_age = text(
            """
            WITH last AS (
              SELECT agent_id, MAX(collected_at) AS last_at
              FROM agent_inventory_snapshots
              GROUP BY agent_id
            )
            SELECT agent_id AS metric,
                   (EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'utc') - last_at)) / 60)::bigint AS value
            FROM last
            WHERE (:agent_id IS NULL OR agent_id = :agent_id)
            ORDER BY value DESC, metric ASC
            LIMIT 50;
            """
        )
        age_rows = db.execute(q_age, {"agent_id": a}).mappings().all()
        inventory_age_by_agent = [{"metric": str(r.get("metric")), "value": int(r.get("value") or 0)} for r in age_rows]

        # -----------------------------
        # Packages count by agent (latest snapshot) - top 50
        # -----------------------------
        q_pkg = text(
            """
            WITH latest AS (
              SELECT DISTINCT ON (agent_id) agent_id, packages_count
              FROM agent_inventory_snapshots
              ORDER BY agent_id, collected_at DESC
            )
            SELECT agent_id AS metric,
                   packages_count::bigint AS value
            FROM latest
            WHERE (:agent_id IS NULL OR agent_id = :agent_id)
            ORDER BY value DESC, metric ASC
            LIMIT 50;
            """
        )
        pkg_rows = db.execute(q_pkg, {"agent_id": a}).mappings().all()
        packages_count_by_agent = [{"metric": str(r.get("metric")), "value": int(r.get("value") or 0)} for r in pkg_rows]

        # -----------------------------
        # Recent inventory warnings
        # -----------------------------
        q_warn = text(
            """
            SELECT
              collected_at AS time,
              agent_id,
              COALESCE(extra->>'warning', extra->>'warnings', extra::text) AS warning
            FROM agent_inventory_snapshots
            WHERE collected_at >= :start_ts
              AND collected_at <= :end_ts
              AND (:agent_id IS NULL OR agent_id = :agent_id)
              AND extra IS NOT NULL
            ORDER BY collected_at DESC
            LIMIT 100;
            """
        )
        warn_rows = db.execute(q_warn, params).mappings().all()
        recent_warnings = [
            {"time": r.get("time").isoformat() if r.get("time") else None, "agent_id": str(r.get("agent_id")), "warning": str(r.get("warning") or "")}
            for r in warn_rows
        ]

        # -----------------------------
        # Fleet health
        # -----------------------------
        q_fleet = text(
            """
            WITH last_inv AS (
              SELECT DISTINCT ON (agent_id)
                agent_id,
                collected_at,
                os,
                packages_count,
                packages_hash,
                manager,
                extra
              FROM agent_inventory_snapshots
              ORDER BY agent_id, collected_at DESC
            )
            SELECT
              a.agent_id,
              a.last_seen_at,
              ROUND(EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'utc') - a.last_seen_at)) / 60.0, 2) AS last_seen_age_min,

              li.collected_at AS last_inventory_at,
              CASE
                WHEN li.collected_at IS NULL THEN NULL
                ELSE ROUND(EXTRACT(EPOCH FROM ((now() AT TIME ZONE 'utc') - li.collected_at)) / 60.0, 2)
              END AS inventory_age_min,

              CASE
                WHEN li.collected_at IS NULL THEN 'no_inventory'
                WHEN li.collected_at < (now() AT TIME ZONE 'utc') - interval '30 minutes' THEN 'stale'
                ELSE 'fresh'
              END AS inventory_status,

              COALESCE(
                NULLIF(li.os->>'pretty_name',''),
                NULLIF(li.os->>'name',''),
                NULLIF(li.os->>'id',''),
                NULLIF(li.os->>'goos',''),
                NULLIF(a.metadata->>'os',''),
                'unknown'
              ) AS os,

              COALESCE(NULLIF(li.manager,''), 'n/a') AS manager,

              li.packages_count,
              li.packages_hash,

              COALESCE(
                jsonb_array_length(COALESCE((li.extra::jsonb)->'warnings','[]'::jsonb)),
                0
              ) AS warnings_count,

              a.is_revoked
            FROM agents a
            LEFT JOIN last_inv li ON li.agent_id = a.agent_id
            WHERE (:agent_id IS NULL OR a.agent_id = :agent_id)
            ORDER BY a.last_seen_at DESC NULLS LAST;
            """
        )
        fleet_rows = db.execute(q_fleet, {"agent_id": a}).mappings().all()
        fleet_health: List[Dict[str, Any]] = []
        for r in fleet_rows:
            fleet_health.append(
                {
                    "agent_id": str(r.get("agent_id")),
                    "last_seen_at": r.get("last_seen_at").isoformat() if r.get("last_seen_at") else None,
                    "last_seen_age_min": float(r.get("last_seen_age_min") or 0),
                    "last_inventory_at": r.get("last_inventory_at").isoformat() if r.get("last_inventory_at") else None,
                    "inventory_age_min": None if r.get("inventory_age_min") is None else float(r.get("inventory_age_min")),
                    "inventory_status": str(r.get("inventory_status")),
                    "os": str(r.get("os") or "unknown"),
                    "manager": str(r.get("manager") or "n/a"),
                    "packages_count": None if r.get("packages_count") is None else int(r.get("packages_count")),
                    "packages_hash": r.get("packages_hash"),
                    "warnings_count": int(r.get("warnings_count") or 0),
                    "is_revoked": bool(r.get("is_revoked")),
                }
            )

        # -----------------------------
        # Recent inventory changes (hash baseline/changes)
        # -----------------------------
        q_recent = text(
            """
            WITH s AS (
              SELECT
                agent_id,
                collected_at,
                packages_hash,
                packages_count,
                LAG(packages_hash) OVER (PARTITION BY agent_id ORDER BY collected_at) AS prev_hash,
                LAG(packages_count) OVER (PARTITION BY agent_id ORDER BY collected_at) AS prev_count
              FROM agent_inventory_snapshots
              WHERE collected_at >= :start_ts
                AND collected_at <= :end_ts
                AND (:agent_id IS NULL OR agent_id = :agent_id)
            )
            SELECT
              collected_at AS time,
              agent_id,
              CASE
                WHEN prev_hash IS NULL THEN 'baseline'
                WHEN prev_hash IS DISTINCT FROM packages_hash THEN 'changed'
                ELSE 'unchanged'
              END AS change_type,
              prev_hash AS old_hash,
              packages_hash AS new_hash,
              prev_count AS old_count,
              packages_count AS new_count
            FROM s
            WHERE prev_hash IS NULL OR prev_hash IS DISTINCT FROM packages_hash
            ORDER BY collected_at DESC
            LIMIT 200;
            """
        )
        rc_rows = db.execute(q_recent, params).mappings().all()
        recent_changes = []
        for r in rc_rows:
            recent_changes.append(
                {
                    "time": r.get("time").isoformat() if r.get("time") else None,
                    "agent_id": str(r.get("agent_id")),
                    "change_type": str(r.get("change_type")),
                    "old_hash": r.get("old_hash"),
                    "new_hash": r.get("new_hash"),
                    "old_count": r.get("old_count"),
                    "new_count": r.get("new_count"),
                }
            )

        return {
            "kpis": kpis,
            "snapshots_per_minute": snapshots_per_minute,
            "changes_per_10m": changes_per_10m,
            "os_distribution": os_distribution,
            "manager_distribution": manager_distribution,
            "inventory_age_by_agent": inventory_age_by_agent,
            "packages_count_by_agent": packages_count_by_agent,
            "recent_warnings": recent_warnings,
            "fleet_health": fleet_health,
            "recent_changes": recent_changes,
            "window_minutes": window_minutes,
            "agent_id": agent_id or "__all",
        }
    finally:
        db.close()
