from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.audit.chain import seal_pruned_range
from app.core.config import settings
from app.core.observability import incr_counter
from app.features.admin.models import AdminAuditEventModel
from app.features.alerts.models import AlertRuleSuppressionHistoryModel, AlertRuleTuningHistoryModel
from app.features.auth.models import PortalLoginEventModel


def _delete_with_limit(session: Session, model: Any, dt_field: Any, cutoff: datetime, id_field: Any, batch: int) -> int:
    rows = (
        session.query(id_field)
        .filter(dt_field < cutoff)
        .order_by(dt_field.asc())
        .limit(batch)
        .all()
    )
    ids = [r[0] for r in rows]
    if not ids:
        return 0
    deleted = session.query(model).filter(id_field.in_(ids)).delete(synchronize_session=False)
    return int(deleted or 0)


def prune_audit_events(session: Session, cutoff: datetime, batch: int) -> int:
    rows = (
        session.query(AdminAuditEventModel.id, AdminAuditEventModel.seq, AdminAuditEventModel.event_hash)
        .filter(AdminAuditEventModel.created_at < cutoff)
        .order_by(AdminAuditEventModel.seq.asc())
        .limit(batch)
        .all()
    )
    if not rows:
        return 0

    seal_pruned_range(
        session,
        from_seq=int(rows[0].seq),
        to_seq=int(rows[-1].seq),
        pruned_count=len(rows),
        last_event_hash=(rows[-1].event_hash or None),
    )
    incr_counter("audit_chain_checkpoints_total")
    deleted = (
        session.query(AdminAuditEventModel)
        .filter(AdminAuditEventModel.id.in_([r.id for r in rows]))
        .delete(synchronize_session=False)
    )
    return int(deleted or 0)


def purge_admin_evidence(session: Session) -> dict[str, int]:
    if not bool(settings.SEAGULL_AUDIT_RETENTION_ENABLED):
        return {"admin_audit_events": 0, "portal_login_events": 0, "rule_tuning_history": 0, "rule_suppression_history": 0}

    now = datetime.utcnow()
    batch = max(100, int(settings.SEAGULL_AUDIT_RETENTION_DELETE_BATCH or 5000))

    audit_cutoff = now - timedelta(days=max(1, int(settings.SEAGULL_AUDIT_RETENTION_DAYS or 180)))
    login_cutoff = now - timedelta(days=max(1, int(settings.SEAGULL_LOGIN_AUDIT_RETENTION_DAYS or settings.SEAGULL_AUDIT_RETENTION_DAYS or 180)))
    governance_cutoff = now - timedelta(days=max(1, int(settings.SEAGULL_GOVERNANCE_RETENTION_DAYS or settings.SEAGULL_AUDIT_RETENTION_DAYS or 180)))

    deleted_admin = prune_audit_events(session, audit_cutoff, batch)
    deleted_login = _delete_with_limit(
        session,
        PortalLoginEventModel,
        PortalLoginEventModel.created_at,
        login_cutoff,
        PortalLoginEventModel.id,
        batch,
    )
    deleted_tuning = _delete_with_limit(
        session,
        AlertRuleTuningHistoryModel,
        AlertRuleTuningHistoryModel.created_at,
        governance_cutoff,
        AlertRuleTuningHistoryModel.id,
        batch,
    )
    deleted_supp = _delete_with_limit(
        session,
        AlertRuleSuppressionHistoryModel,
        AlertRuleSuppressionHistoryModel.created_at,
        governance_cutoff,
        AlertRuleSuppressionHistoryModel.id,
        batch,
    )

    return {
        "admin_audit_events": deleted_admin,
        "portal_login_events": deleted_login,
        "rule_tuning_history": deleted_tuning,
        "rule_suppression_history": deleted_supp,
    }
