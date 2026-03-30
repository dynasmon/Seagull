import hashlib
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import String, and_, cast, func, literal, or_, select

from app.core.agent_auth import AgentPrincipal, get_current_agent
from app.core.config import settings
from app.core.portal_auth import get_current_user
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.db import SessionLocal
from app.core.redis_client import get_redis
from app.core.observability import incr_counter, observe_hist
from app.features.agents.models import AgentModel
from app.features.inventory.models import AgentInventoryLatestModel, AgentInventorySnapshotModel
from app.shared.schemas import CursorPage
from app.features.inventory.schemas import InventorySnapshotIn, InventorySnapshotOut, PackageEntry


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


def _cache_get_json(key: str) -> Optional[Dict[str, Any]]:
    r = get_redis()
    if r is None:
        return None
    try:
        raw = r.get(key)
        if not raw:
            return None
        out = json.loads(raw)
        return out if isinstance(out, dict) else None
    except Exception:
        return None


def _cache_set_json(key: str, payload: Dict[str, Any], ttl_s: int) -> None:
    if ttl_s <= 0:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.setex(key, int(ttl_s), json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
    except Exception:
        return


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
        db.flush()
        latest_ins = insert(AgentInventoryLatestModel).values(
            agent_id=agent.agent_id,
            snapshot_id=int(row.id),
            collected_at=row.collected_at,
            os=row.os,
            packages_count=int(row.packages_count or 0),
            packages_hash=row.packages_hash,
            manager=row.manager,
            extra=row.extra,
        )
        db.execute(
            latest_ins.on_conflict_do_update(
                index_elements=[AgentInventoryLatestModel.agent_id],
                set_={
                    "snapshot_id": latest_ins.excluded.snapshot_id,
                    "collected_at": latest_ins.excluded.collected_at,
                    "os": latest_ins.excluded.os,
                    "packages_count": latest_ins.excluded.packages_count,
                    "packages_hash": latest_ins.excluded.packages_hash,
                    "manager": latest_ins.excluded.manager,
                    "extra": latest_ins.excluded.extra,
                    "updated_at": func.now(),
                },
                where=(latest_ins.excluded.collected_at >= AgentInventoryLatestModel.collected_at),
            )
        )
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


@router.get("/me/history/page", response_model=CursorPage[InventorySnapshotOut])
async def get_my_inventory_history_page(
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent: AgentPrincipal = Depends(get_current_agent),
):
    """Cursor-paginated inventory history (agent-auth).

    Recommended replacement for `/inventory/me/history` when you want paging.
    """

    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent.agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc(), AgentInventorySnapshotModel.id.desc())
        )

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            stmt = stmt.where(
                or_(
                    AgentInventorySnapshotModel.collected_at < c_ts,
                    and_(AgentInventorySnapshotModel.collected_at == c_ts, AgentInventorySnapshotModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(page_size + 1)).scalars().all()
        has_more = len(rows) > page_size
        items = rows[:page_size]

        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = make_cursor_ts_id(last.collected_at, last.id)

        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
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


@router.get("/{agent_id}/history/page", response_model=CursorPage[InventorySnapshotOut])
async def get_agent_inventory_history_page(
    agent_id: str,
    page_size: int = Query(50, ge=1, le=200, description="Page size (max 200)"),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    _user=Depends(get_current_user),
):
    """Cursor-paginated inventory history (portal-auth)."""

    db = SessionLocal()
    try:
        stmt = (
            select(AgentInventorySnapshotModel)
            .where(AgentInventorySnapshotModel.agent_id == agent_id)
            .order_by(AgentInventorySnapshotModel.collected_at.desc(), AgentInventorySnapshotModel.id.desc())
        )

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            stmt = stmt.where(
                or_(
                    AgentInventorySnapshotModel.collected_at < c_ts,
                    and_(AgentInventorySnapshotModel.collected_at == c_ts, AgentInventorySnapshotModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(page_size + 1)).scalars().all()
        has_more = len(rows) > page_size
        items = rows[:page_size]

        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = make_cursor_ts_id(last.collected_at, last.id)

        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
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

    started = time.perf_counter()
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

    cache_key = f"netwatch:inventory:overview:v2:w={int(window_minutes)}:a={a or '*'}"
    cached = _cache_get_json(cache_key)
    if cached is not None:
        incr_counter("api_cache_hit_total", route="/inventory/overview")
        return cached

    db = SessionLocal()
    try:
        # -----------------------------
        # KPIs
        # -----------------------------
        agents_total = int(db.execute(select(func.count()).select_from(AgentModel)).scalar() or 0)

        online_stmt = select(func.count()).select_from(AgentModel).where(AgentModel.last_seen_at >= now - timedelta(minutes=5))
        if a is not None:
            online_stmt = online_stmt.where(AgentModel.agent_id == a)
        agents_online_5m = int(db.execute(online_stmt).scalar() or 0)

        inv_6h_stmt = (
            select(func.count())
            .select_from(AgentInventoryLatestModel)
            .where(AgentInventoryLatestModel.collected_at >= now - timedelta(hours=6))
        )
        if a is not None:
            inv_6h_stmt = inv_6h_stmt.where(AgentInventoryLatestModel.agent_id == a)
        agents_with_inventory_6h = int(db.execute(inv_6h_stmt).scalar() or 0)

        last_inv_stmt = (
            select(
                AgentInventoryLatestModel.agent_id.label("agent_id"),
                AgentInventoryLatestModel.collected_at.label("last_at"),
            )
        )
        if a is not None:
            last_inv_stmt = last_inv_stmt.where(AgentInventoryLatestModel.agent_id == a)
        last_inv_rows = db.execute(last_inv_stmt).all()
        oldest_inventory_age_minutes = 0
        if last_inv_rows:
            oldest_inventory_age_minutes = int(
                max(max((now - (r.last_at or now)).total_seconds() / 60.0, 0) for r in last_inv_rows)
            )

        kpis = {
            "agents_total": agents_total,
            "agents_online_5m": agents_online_5m,
            "agents_with_inventory_6h": agents_with_inventory_6h,
            "oldest_inventory_age_minutes": oldest_inventory_age_minutes,
        }

        # -----------------------------
        # Inventory snapshots per minute
        # -----------------------------
        snap_stmt = (
            select(
                func.date_trunc("minute", AgentInventorySnapshotModel.collected_at).label("bucket_ts"),
                func.count().label("value"),
            )
            .where(
                AgentInventorySnapshotModel.collected_at >= start_ts,
                AgentInventorySnapshotModel.collected_at <= now,
            )
            .group_by("bucket_ts")
            .order_by("bucket_ts")
        )
        if a is not None:
            snap_stmt = snap_stmt.where(AgentInventorySnapshotModel.agent_id == a)
        snap_rows = db.execute(snap_stmt).all()
        snap_map = {r.bucket_ts: int(r.value or 0) for r in snap_rows}
        snap_data = []
        bucket = start_1m
        while bucket <= end_1m:
            snap_data.append({"t": _fmt_hhmm(bucket), "value": snap_map.get(bucket, 0)})
            bucket += timedelta(minutes=1)
        snapshots_per_minute = {
            "series": ["value"],
            "data": snap_data,
        }

        # -----------------------------
        # Inventory changes per 10m (packages hash)
        # -----------------------------
        prev_hash_col = func.lag(AgentInventorySnapshotModel.packages_hash).over(
            partition_by=AgentInventorySnapshotModel.agent_id,
            order_by=AgentInventorySnapshotModel.collected_at,
        )
        ch_base_stmt = select(
            AgentInventorySnapshotModel.collected_at.label("collected_at"),
            prev_hash_col.label("prev_hash"),
            AgentInventorySnapshotModel.packages_hash.label("packages_hash"),
        ).where(
            AgentInventorySnapshotModel.collected_at >= start_ts,
            AgentInventorySnapshotModel.collected_at <= now,
        )
        if a is not None:
            ch_base_stmt = ch_base_stmt.where(AgentInventorySnapshotModel.agent_id == a)
        ch_subq = ch_base_stmt.subquery()
        ch_rows = db.execute(
            select(ch_subq.c.collected_at)
            .where(or_(ch_subq.c.prev_hash.is_(None), ch_subq.c.prev_hash != ch_subq.c.packages_hash))
            .order_by(ch_subq.c.collected_at.asc())
        ).all()
        ch_counts: Dict[datetime, int] = {}
        for r in ch_rows:
            t = _floor_dt(r.collected_at, 10)
            ch_counts[t] = ch_counts.get(t, 0) + 1
        ch_data = []
        bucket = start_10m
        while bucket <= end_10m:
            ch_data.append({"t": _fmt_hhmm(bucket), "value": int(ch_counts.get(bucket, 0))})
            bucket += timedelta(minutes=10)
        changes_per_10m = {
            "series": ["value"],
            "data": ch_data,
        }

        # -----------------------------
        # OS distribution (latest snapshot per agent within window)
        # -----------------------------
        latest_os_stmt = select(
            AgentInventoryLatestModel.agent_id.label("agent_id"),
            AgentInventoryLatestModel.os.label("os"),
        ).where(
            AgentInventoryLatestModel.collected_at >= start_ts,
            AgentInventoryLatestModel.collected_at <= now,
        )
        if a is not None:
            latest_os_stmt = latest_os_stmt.where(AgentInventoryLatestModel.agent_id == a)
        latest_os_subq = latest_os_stmt.subquery()
        os_label = func.coalesce(
            func.nullif(latest_os_subq.c.os["pretty_name"].astext, ""),
            func.nullif(latest_os_subq.c.os["name"].astext, ""),
            latest_os_subq.c.os["id"].astext,
            latest_os_subq.c.os["goos"].astext,
            literal("unknown"),
        ).label("os")
        os_rows = db.execute(
            select(os_label, func.count().label("agents"))
            .group_by(os_label)
            .order_by(func.count().desc(), os_label.asc())
        ).all()
        os_distribution = [{"os": str(r.os or "unknown"), "agents": int(r.agents or 0)} for r in os_rows]

        # -----------------------------
        # Package manager distribution (latest snapshot per agent within window)
        # -----------------------------
        latest_mgr_stmt = select(
            AgentInventoryLatestModel.agent_id.label("agent_id"),
            AgentInventoryLatestModel.manager.label("manager"),
        ).where(
            AgentInventoryLatestModel.collected_at >= start_ts,
            AgentInventoryLatestModel.collected_at <= now,
        )
        if a is not None:
            latest_mgr_stmt = latest_mgr_stmt.where(AgentInventoryLatestModel.agent_id == a)
        latest_mgr_subq = latest_mgr_stmt.subquery()
        mgr_label = func.coalesce(func.nullif(latest_mgr_subq.c.manager, ""), literal("unknown")).label("manager")
        mgr_rows = db.execute(
            select(mgr_label, func.count().label("agents"))
            .group_by(mgr_label)
            .order_by(func.count().desc(), mgr_label.asc())
        ).all()
        manager_distribution = [{"manager": str(r.manager or "unknown"), "agents": int(r.agents or 0)} for r in mgr_rows]

        # -----------------------------
        # Inventory age by agent (minutes) - top 50
        # -----------------------------
        age_rows = []
        for r in last_inv_rows:
            age_rows.append(
                {
                    "metric": str(r.agent_id),
                    "value": int(max((now - (r.last_at or now)).total_seconds() / 60.0, 0)),
                }
            )
        age_rows.sort(key=lambda x: (-x["value"], x["metric"]))
        inventory_age_by_agent = age_rows[:50]

        # -----------------------------
        # Packages count by agent (latest snapshot) - top 50
        # -----------------------------
        latest_pkg_subq = select(
            AgentInventoryLatestModel.agent_id.label("agent_id"),
            AgentInventoryLatestModel.packages_count.label("packages_count"),
            AgentInventoryLatestModel.collected_at.label("collected_at"),
        ).subquery()
        pkg_stmt = (
            select(
                latest_pkg_subq.c.agent_id.label("metric"),
                latest_pkg_subq.c.packages_count.label("value"),
            )
            .where(
                latest_pkg_subq.c.collected_at >= start_ts,
                latest_pkg_subq.c.collected_at <= now,
            )
            .order_by(latest_pkg_subq.c.packages_count.desc(), latest_pkg_subq.c.agent_id.asc())
            .limit(50)
        )
        if a is not None:
            pkg_stmt = pkg_stmt.where(latest_pkg_subq.c.agent_id == a)
        pkg_rows = db.execute(pkg_stmt).all()
        packages_count_by_agent = [{"metric": str(r.metric), "value": int(r.value or 0)} for r in pkg_rows]

        # -----------------------------
        # Recent inventory warnings
        # -----------------------------
        warn_expr = func.coalesce(
            AgentInventorySnapshotModel.extra["warning"].astext,
            AgentInventorySnapshotModel.extra["warnings"].astext,
            cast(AgentInventorySnapshotModel.extra, String),
        ).label("warning")
        warn_stmt = (
            select(
                AgentInventorySnapshotModel.collected_at.label("time"),
                AgentInventorySnapshotModel.agent_id.label("agent_id"),
                warn_expr,
            )
            .where(
                AgentInventorySnapshotModel.collected_at >= start_ts,
                AgentInventorySnapshotModel.collected_at <= now,
                AgentInventorySnapshotModel.extra.is_not(None),
            )
            .order_by(AgentInventorySnapshotModel.collected_at.desc())
            .limit(100)
        )
        if a is not None:
            warn_stmt = warn_stmt.where(AgentInventorySnapshotModel.agent_id == a)
        warn_rows = db.execute(warn_stmt).all()
        recent_warnings = [
            {"time": r.time.isoformat() if r.time else None, "agent_id": str(r.agent_id), "warning": str(r.warning or "")}
            for r in warn_rows
        ]

        # -----------------------------
        # Fleet health
        # -----------------------------
        agent_stmt = select(AgentModel)
        if a is not None:
            agent_stmt = agent_stmt.where(AgentModel.agent_id == a)
        agents = db.execute(agent_stmt).scalars().all()

        latest_inv_stmt = select(
            AgentInventoryLatestModel.agent_id.label("agent_id"),
            AgentInventoryLatestModel.collected_at.label("collected_at"),
            AgentInventoryLatestModel.os.label("os"),
            AgentInventoryLatestModel.packages_count.label("packages_count"),
            AgentInventoryLatestModel.packages_hash.label("packages_hash"),
            AgentInventoryLatestModel.manager.label("manager"),
            AgentInventoryLatestModel.extra.label("extra"),
        )
        if a is not None:
            latest_inv_stmt = latest_inv_stmt.where(AgentInventoryLatestModel.agent_id == a)
        latest_inv_rows = db.execute(latest_inv_stmt).mappings().all()
        latest_by_agent = {str(r.get("agent_id")): r for r in latest_inv_rows}

        fleet_health: List[Dict[str, Any]] = []
        for agent_row in agents:
            inv = latest_by_agent.get(str(agent_row.agent_id))
            last_seen_at = agent_row.last_seen_at
            last_seen_age = 0.0
            if last_seen_at is not None:
                if last_seen_at.tzinfo is None:
                    last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
                last_seen_age = round(max((now - last_seen_at).total_seconds() / 60.0, 0), 2)

            last_inventory_at = inv.get("collected_at") if inv else None
            inventory_age = None
            if last_inventory_at is not None:
                if last_inventory_at.tzinfo is None:
                    last_inventory_at = last_inventory_at.replace(tzinfo=timezone.utc)
                inventory_age = round(max((now - last_inventory_at).total_seconds() / 60.0, 0), 2)

            if last_inventory_at is None:
                inventory_status = "no_inventory"
            elif inventory_age is not None and inventory_age > 30:
                inventory_status = "stale"
            else:
                inventory_status = "fresh"

            inv_os = (inv.get("os") if inv else None) or {}
            agent_meta = (agent_row.agent_metadata or {}) if hasattr(agent_row, "agent_metadata") else {}
            os_name = (
                inv_os.get("pretty_name")
                or inv_os.get("name")
                or inv_os.get("id")
                or inv_os.get("goos")
                or agent_meta.get("os")
                or "unknown"
            )

            manager = ((inv.get("manager") if inv else None) or "").strip() or "n/a"
            extra = (inv.get("extra") if inv else None) or {}
            warnings = extra.get("warnings")
            warnings_count = len(warnings) if isinstance(warnings, list) else 0

            fleet_health.append(
                {
                    "agent_id": str(agent_row.agent_id),
                    "last_seen_at": last_seen_at.isoformat() if last_seen_at else None,
                    "last_seen_age_min": float(last_seen_age),
                    "last_inventory_at": last_inventory_at.isoformat() if last_inventory_at else None,
                    "inventory_age_min": None if inventory_age is None else float(inventory_age),
                    "inventory_status": inventory_status,
                    "os": str(os_name),
                    "manager": manager,
                    "packages_count": None if inv is None or inv.get("packages_count") is None else int(inv.get("packages_count")),
                    "packages_hash": None if inv is None else inv.get("packages_hash"),
                    "warnings_count": int(warnings_count),
                    "is_revoked": bool(agent_row.is_revoked),
                }
            )
        fleet_health.sort(
            key=lambda x: x["last_seen_at"] or "",
            reverse=True,
        )

        # -----------------------------
        # Recent inventory changes (hash baseline/changes)
        # -----------------------------
        prev_hash = func.lag(AgentInventorySnapshotModel.packages_hash).over(
            partition_by=AgentInventorySnapshotModel.agent_id,
            order_by=AgentInventorySnapshotModel.collected_at,
        )
        prev_count = func.lag(AgentInventorySnapshotModel.packages_count).over(
            partition_by=AgentInventorySnapshotModel.agent_id,
            order_by=AgentInventorySnapshotModel.collected_at,
        )
        recent_base_stmt = select(
            AgentInventorySnapshotModel.collected_at.label("time"),
            AgentInventorySnapshotModel.agent_id.label("agent_id"),
            AgentInventorySnapshotModel.packages_hash.label("new_hash"),
            AgentInventorySnapshotModel.packages_count.label("new_count"),
            prev_hash.label("old_hash"),
            prev_count.label("old_count"),
        ).where(
            AgentInventorySnapshotModel.collected_at >= start_ts,
            AgentInventorySnapshotModel.collected_at <= now,
        )
        if a is not None:
            recent_base_stmt = recent_base_stmt.where(AgentInventorySnapshotModel.agent_id == a)
        recent_subq = recent_base_stmt.subquery()
        rc_rows = db.execute(
            select(recent_subq)
            .where(or_(recent_subq.c.old_hash.is_(None), recent_subq.c.old_hash != recent_subq.c.new_hash))
            .order_by(recent_subq.c.time.desc())
            .limit(200)
        ).mappings().all()
        recent_changes = []
        for r in rc_rows:
            old_hash = r.get("old_hash")
            new_hash = r.get("new_hash")
            change_type = "baseline" if old_hash is None else ("changed" if old_hash != new_hash else "unchanged")
            recent_changes.append(
                {
                    "time": r.get("time").isoformat() if r.get("time") else None,
                    "agent_id": str(r.get("agent_id")),
                    "change_type": change_type,
                    "old_hash": old_hash,
                    "new_hash": new_hash,
                    "old_count": r.get("old_count"),
                    "new_count": r.get("new_count"),
                }
            )

        payload = {
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
        _cache_set_json(cache_key, payload, int(getattr(settings, "NETWATCH_EVENTS_SUMMARY_CACHE_TTL_SECONDS", 15) or 15))
        observe_hist("api_route_latency_seconds", time.perf_counter() - started, route="/inventory/overview")
        return payload
    finally:
        db.close()
