from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import String, and_, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.features.agents.models import AgentModel
from app.features.inventory.models import AgentInventoryLatestModel, AgentInventorySnapshotModel


def create_snapshot_and_upsert_latest(
    db: Session,
    *,
    agent_id: str,
    collected_at: datetime,
    schema_version: int,
    os_data: dict[str, Any],
    packages_data: list[dict[str, Any]],
    packages_hash: str,
    packages_count: int,
    manager: str | None,
    extra: dict[str, Any],
) -> int:
    row = AgentInventorySnapshotModel(
        agent_id=agent_id,
        collected_at=collected_at,
        schema_version=schema_version,
        os=os_data,
        packages=packages_data,
        packages_hash=packages_hash,
        packages_count=packages_count,
        manager=manager,
        extra=extra,
    )
    db.add(row)
    db.flush()

    latest_ins = insert(AgentInventoryLatestModel).values(
        agent_id=agent_id,
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
    return int(row.id)


def get_latest_snapshot(db: Session, agent_id: str) -> AgentInventorySnapshotModel | None:
    stmt = (
        select(AgentInventorySnapshotModel)
        .where(AgentInventorySnapshotModel.agent_id == agent_id)
        .order_by(AgentInventorySnapshotModel.collected_at.desc())
        .limit(1)
    )
    return db.execute(stmt).scalars().first()


def list_snapshot_history(db: Session, agent_id: str, limit: int) -> list[AgentInventorySnapshotModel]:
    stmt = (
        select(AgentInventorySnapshotModel)
        .where(AgentInventorySnapshotModel.agent_id == agent_id)
        .order_by(AgentInventorySnapshotModel.collected_at.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def list_snapshot_history_page(
    db: Session,
    *,
    agent_id: str,
    page_size: int,
    cursor_parsed: tuple[datetime, int] | None,
) -> list[AgentInventorySnapshotModel]:
    stmt = (
        select(AgentInventorySnapshotModel)
        .where(AgentInventorySnapshotModel.agent_id == agent_id)
        .order_by(AgentInventorySnapshotModel.collected_at.desc(), AgentInventorySnapshotModel.id.desc())
    )
    if cursor_parsed:
        c_ts, c_id = cursor_parsed
        stmt = stmt.where(
            or_(
                AgentInventorySnapshotModel.collected_at < c_ts,
                and_(AgentInventorySnapshotModel.collected_at == c_ts, AgentInventorySnapshotModel.id < c_id),
            )
        )
    return db.execute(stmt.limit(page_size + 1)).scalars().all()


def fetch_overview_payload(
    db: Session,
    *,
    now: datetime,
    start_ts: datetime,
    start_1m: datetime,
    start_10m: datetime,
    end_1m: datetime,
    end_10m: datetime,
    agent_filter: str | None,
    fmt_hhmm,
    floor_dt,
) -> dict[str, Any]:
    agents_total = int(db.execute(select(func.count()).select_from(AgentModel)).scalar() or 0)

    online_stmt = select(func.count()).select_from(AgentModel).where(AgentModel.last_seen_at >= now - timedelta(minutes=5))
    if agent_filter is not None:
        online_stmt = online_stmt.where(AgentModel.agent_id == agent_filter)
    agents_online_5m = int(db.execute(online_stmt).scalar() or 0)

    inv_6h_stmt = (
        select(func.count())
        .select_from(AgentInventoryLatestModel)
        .where(AgentInventoryLatestModel.collected_at >= now - timedelta(hours=6))
    )
    if agent_filter is not None:
        inv_6h_stmt = inv_6h_stmt.where(AgentInventoryLatestModel.agent_id == agent_filter)
    agents_with_inventory_6h = int(db.execute(inv_6h_stmt).scalar() or 0)

    last_inv_stmt = select(
        AgentInventoryLatestModel.agent_id.label("agent_id"),
        AgentInventoryLatestModel.collected_at.label("last_at"),
    )
    if agent_filter is not None:
        last_inv_stmt = last_inv_stmt.where(AgentInventoryLatestModel.agent_id == agent_filter)
    last_inv_rows = db.execute(last_inv_stmt).all()

    oldest_inventory_age_minutes = 0
    if last_inv_rows:
        oldest_inventory_age_minutes = int(max(max((now - (r.last_at or now)).total_seconds() / 60.0, 0) for r in last_inv_rows))

    kpis = {
        "agents_total": agents_total,
        "agents_online_5m": agents_online_5m,
        "agents_with_inventory_6h": agents_with_inventory_6h,
        "oldest_inventory_age_minutes": oldest_inventory_age_minutes,
    }

    snap_stmt = (
        select(
            func.date_trunc("minute", AgentInventorySnapshotModel.collected_at).label("bucket_ts"),
            func.count().label("value"),
        )
        .where(AgentInventorySnapshotModel.collected_at >= start_ts, AgentInventorySnapshotModel.collected_at <= now)
        .group_by("bucket_ts")
        .order_by("bucket_ts")
    )
    if agent_filter is not None:
        snap_stmt = snap_stmt.where(AgentInventorySnapshotModel.agent_id == agent_filter)
    snap_rows = db.execute(snap_stmt).all()
    snap_map = {r.bucket_ts: int(r.value or 0) for r in snap_rows}

    snap_data = []
    bucket = start_1m
    while bucket <= end_1m:
        snap_data.append({"t": fmt_hhmm(bucket), "value": snap_map.get(bucket, 0)})
        bucket += timedelta(minutes=1)

    snapshots_per_minute = {"series": ["value"], "data": snap_data}

    prev_hash_col = func.lag(AgentInventorySnapshotModel.packages_hash).over(
        partition_by=AgentInventorySnapshotModel.agent_id,
        order_by=AgentInventorySnapshotModel.collected_at,
    )
    ch_base_stmt = select(
        AgentInventorySnapshotModel.collected_at.label("collected_at"),
        prev_hash_col.label("prev_hash"),
        AgentInventorySnapshotModel.packages_hash.label("packages_hash"),
    ).where(AgentInventorySnapshotModel.collected_at >= start_ts, AgentInventorySnapshotModel.collected_at <= now)
    if agent_filter is not None:
        ch_base_stmt = ch_base_stmt.where(AgentInventorySnapshotModel.agent_id == agent_filter)
    ch_subq = ch_base_stmt.subquery()
    ch_rows = db.execute(
        select(ch_subq.c.collected_at)
        .where(or_(ch_subq.c.prev_hash.is_(None), ch_subq.c.prev_hash != ch_subq.c.packages_hash))
        .order_by(ch_subq.c.collected_at.asc())
    ).all()

    ch_counts: dict[datetime, int] = {}
    for r in ch_rows:
        t = floor_dt(r.collected_at, 10)
        ch_counts[t] = ch_counts.get(t, 0) + 1

    ch_data = []
    bucket = start_10m
    while bucket <= end_10m:
        ch_data.append({"t": fmt_hhmm(bucket), "value": int(ch_counts.get(bucket, 0))})
        bucket += timedelta(minutes=10)

    changes_per_10m = {"series": ["value"], "data": ch_data}

    latest_os_stmt = select(
        AgentInventoryLatestModel.agent_id.label("agent_id"),
        AgentInventoryLatestModel.os.label("os"),
    ).where(AgentInventoryLatestModel.collected_at >= start_ts, AgentInventoryLatestModel.collected_at <= now)
    if agent_filter is not None:
        latest_os_stmt = latest_os_stmt.where(AgentInventoryLatestModel.agent_id == agent_filter)
    latest_os_subq = latest_os_stmt.subquery()
    os_label = func.coalesce(
        func.nullif(latest_os_subq.c.os["pretty_name"].astext, ""),
        func.nullif(latest_os_subq.c.os["name"].astext, ""),
        latest_os_subq.c.os["id"].astext,
        latest_os_subq.c.os["goos"].astext,
        literal("unknown"),
    ).label("os")
    os_rows = db.execute(select(os_label, func.count().label("agents")).group_by(os_label).order_by(func.count().desc(), os_label.asc())).all()
    os_distribution = [{"os": str(r.os or "unknown"), "agents": int(r.agents or 0)} for r in os_rows]

    latest_mgr_stmt = select(
        AgentInventoryLatestModel.agent_id.label("agent_id"),
        AgentInventoryLatestModel.manager.label("manager"),
    ).where(AgentInventoryLatestModel.collected_at >= start_ts, AgentInventoryLatestModel.collected_at <= now)
    if agent_filter is not None:
        latest_mgr_stmt = latest_mgr_stmt.where(AgentInventoryLatestModel.agent_id == agent_filter)
    latest_mgr_subq = latest_mgr_stmt.subquery()
    mgr_label = func.coalesce(func.nullif(latest_mgr_subq.c.manager, ""), literal("unknown")).label("manager")
    mgr_rows = db.execute(
        select(mgr_label, func.count().label("agents")).group_by(mgr_label).order_by(func.count().desc(), mgr_label.asc())
    ).all()
    manager_distribution = [{"manager": str(r.manager or "unknown"), "agents": int(r.agents or 0)} for r in mgr_rows]

    age_rows = [{"metric": str(r.agent_id), "value": int(max((now - (r.last_at or now)).total_seconds() / 60.0, 0))} for r in last_inv_rows]
    age_rows.sort(key=lambda x: (-x["value"], x["metric"]))
    inventory_age_by_agent = age_rows[:50]

    latest_pkg_subq = select(
        AgentInventoryLatestModel.agent_id.label("agent_id"),
        AgentInventoryLatestModel.packages_count.label("packages_count"),
        AgentInventoryLatestModel.collected_at.label("collected_at"),
    ).subquery()
    pkg_stmt = (
        select(latest_pkg_subq.c.agent_id.label("metric"), latest_pkg_subq.c.packages_count.label("value"))
        .where(latest_pkg_subq.c.collected_at >= start_ts, latest_pkg_subq.c.collected_at <= now)
        .order_by(latest_pkg_subq.c.packages_count.desc(), latest_pkg_subq.c.agent_id.asc())
        .limit(50)
    )
    if agent_filter is not None:
        pkg_stmt = pkg_stmt.where(latest_pkg_subq.c.agent_id == agent_filter)
    pkg_rows = db.execute(pkg_stmt).all()
    packages_count_by_agent = [{"metric": str(r.metric), "value": int(r.value or 0)} for r in pkg_rows]

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
    if agent_filter is not None:
        warn_stmt = warn_stmt.where(AgentInventorySnapshotModel.agent_id == agent_filter)
    warn_rows = db.execute(warn_stmt).all()
    recent_warnings = [
        {"time": r.time.isoformat() if r.time else None, "agent_id": str(r.agent_id), "warning": str(r.warning or "")}
        for r in warn_rows
    ]

    agent_stmt = select(AgentModel)
    if agent_filter is not None:
        agent_stmt = agent_stmt.where(AgentModel.agent_id == agent_filter)
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
    if agent_filter is not None:
        latest_inv_stmt = latest_inv_stmt.where(AgentInventoryLatestModel.agent_id == agent_filter)
    latest_inv_rows2 = db.execute(latest_inv_stmt).mappings().all()
    latest_by_agent = {str(r.get("agent_id")): r for r in latest_inv_rows2}

    fleet_health: list[dict[str, Any]] = []
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
    fleet_health.sort(key=lambda x: x["last_seen_at"] or "", reverse=True)

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
    ).where(AgentInventorySnapshotModel.collected_at >= start_ts, AgentInventorySnapshotModel.collected_at <= now)
    if agent_filter is not None:
        recent_base_stmt = recent_base_stmt.where(AgentInventorySnapshotModel.agent_id == agent_filter)
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
    }
