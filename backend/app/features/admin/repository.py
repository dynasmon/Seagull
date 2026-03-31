from __future__ import annotations

from datetime import datetime

from sqlalchemy import and_, case, func, select, text
from sqlalchemy.orm import Session

from app.features.admin.models import AdminAuditEventModel
from app.features.agents.models import AgentModel
from app.features.auth.models import PortalLoginEventModel, PortalUserModel
from app.features.inventory.models import AgentInventorySnapshotModel


def list_audit_events(
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
) -> list[AdminAuditEventModel]:
    q = db.query(AdminAuditEventModel).order_by(AdminAuditEventModel.created_at.desc(), AdminAuditEventModel.id.desc())
    if event_type:
        q = q.filter(AdminAuditEventModel.event_type == event_type)
    if action:
        q = q.filter(AdminAuditEventModel.action == action)
    if outcome:
        q = q.filter(AdminAuditEventModel.outcome == outcome)
    if resource_type:
        q = q.filter(AdminAuditEventModel.resource_type == resource_type)
    if actor_username:
        q = q.filter(AdminAuditEventModel.actor_username == actor_username)
    if since is not None:
        q = q.filter(AdminAuditEventModel.created_at >= since)
    if until is not None:
        q = q.filter(AdminAuditEventModel.created_at <= until)
    return q.limit(limit + 1).all()


def list_admin_login_events(db: Session, *, limit: int, include_failed: bool) -> list[PortalLoginEventModel]:
    q = (
        db.query(PortalLoginEventModel)
        .join(PortalUserModel, PortalUserModel.username == PortalLoginEventModel.username)
        .filter(PortalUserModel.role == "admin")
        .order_by(PortalLoginEventModel.created_at.desc())
    )
    if not include_failed:
        q = q.filter(PortalLoginEventModel.succeeded.is_(True))
    return q.limit(limit).all()


def probe_database(db: Session) -> None:
    db.execute(text("SELECT 1"))


def count_total_agents(db: Session) -> int:
    return int(db.execute(select(func.count()).select_from(AgentModel)).scalar() or 0)


def count_online_agents(db: Session, *, online_cutoff: datetime) -> int:
    return int(
        db.execute(
            select(func.count()).select_from(AgentModel).where(
                and_(AgentModel.is_revoked.is_(False), AgentModel.last_seen_at.is_not(None), AgentModel.last_seen_at >= online_cutoff)
            )
        ).scalar()
        or 0
    )


def count_revoked_agents(db: Session) -> int:
    return int(db.execute(select(func.count()).select_from(AgentModel).where(AgentModel.is_revoked.is_(True))).scalar() or 0)


def inventory_status_counts(db: Session, *, inventory_stale_cutoff: datetime) -> tuple[int, int, int]:
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
    return inv_no, inv_stale, inv_fresh
