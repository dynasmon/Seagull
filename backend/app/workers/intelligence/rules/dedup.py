from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.features.alerts.models import AlertModel


def _normalize_dedup_key(rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]):
    """Normalize dedup key so enrichment doesn't create duplicate alerts."""
    rid = str(rule_id or "")
    src = src_ip
    dst = dst_ip

    if rid.startswith(("ddos_", "dos_", "l7_")):
        src = None
    if rid.startswith("ssh_bruteforce_"):
        dst = None

    return (rid, src, dst, int(dst_port) if dst_port is not None else None)


def _recent_alert_index(
    db: Session, horizon: timedelta
) -> Dict[Tuple[str, Optional[str], Optional[str], Optional[int]], datetime]:
    threshold = datetime.utcnow() - horizon

    stmt = (
        select(
            AlertModel.rule_id,
            AlertModel.src_ip,
            AlertModel.dst_ip,
            AlertModel.dst_port,
            func.max(AlertModel.created_at),
        )
        .where(AlertModel.created_at >= threshold)
        .group_by(AlertModel.rule_id, AlertModel.src_ip, AlertModel.dst_ip, AlertModel.dst_port)
    )

    rows = db.execute(stmt).all()
    idx: Dict[Tuple[str, Optional[str], Optional[str], Optional[int]], datetime] = {}
    for rule_id, src_ip, dst_ip, dst_port, last_at in rows:
        key = _normalize_dedup_key(rule_id, src_ip, dst_ip, dst_port)
        idx[key] = last_at

    return idx


def _recent_alert_last_at(
    idx: Dict, rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]
) -> Optional[datetime]:
    return idx.get(_normalize_dedup_key(rule_id, src_ip, dst_ip, dst_port))


def _recent_alert_exists_cached(
    idx: Dict, rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]
) -> bool:
    return _recent_alert_last_at(idx, rule_id, src_ip, dst_ip, dst_port) is not None


def _index_add(idx: Dict, rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]):
    idx[_normalize_dedup_key(rule_id, src_ip, dst_ip, dst_port)] = datetime.utcnow()
