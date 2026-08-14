from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Sequence

from sqlalchemy.orm import Session

from app.core.config import settings
from app.features.admin.models import AdminAuditEventModel, AuditChainCheckpointModel, AuditChainHeadModel

CHAIN_HEAD_ID = 1

BREAK_PREV_HASH_MISMATCH = "prev_hash_mismatch"
BREAK_EVENT_HASH_MISMATCH = "event_hash_mismatch"
BREAK_MISSING_PREDECESSOR = "missing_predecessor"
BREAK_SEQ_GAP = "seq_gap"


@dataclass(frozen=True)
class ChainBreak:
    seq: int
    event_id: str
    reason: str


@dataclass(frozen=True)
class ChainPage:
    checked: int
    last_seq: int
    breaks: tuple[ChainBreak, ...]
    exhausted: bool


def _secret() -> str:
    return (
        settings.SEAGULL_AUDIT_HASH_PEPPER
        or settings.token_pepper()
        or settings.SEAGULL_JWT_SECRET
        or ""
    ).strip()


def _stable_json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def _digest(message: str) -> str:
    raw = message.encode("utf-8")
    secret = _secret()
    if secret:
        return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def event_payload(row: AdminAuditEventModel) -> dict[str, Any]:
    return {
        "seq": int(row.seq or 0),
        "id": row.id,
        "operation_id": row.operation_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "event_type": row.event_type,
        "action": row.action,
        "outcome": row.outcome,
        "actor_user_id": row.actor_user_id,
        "actor_username": row.actor_username,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "request_id": row.request_id,
        "trace_id": row.trace_id,
        "ip": row.ip,
        "user_agent": row.user_agent,
        "method": row.method,
        "path": row.path,
        "reason": row.reason,
        "error": row.error,
        "before": row.before,
        "after": row.after,
        "changed_fields": row.changed_fields,
        "context": row.context,
        "schema_version": int(row.schema_version or 1),
    }


def sign_event(payload: dict[str, Any], prev_hash: Optional[str]) -> str:
    return _digest(_stable_json({"payload": payload, "prev_event_hash": prev_hash or ""}))


def checkpoint_payload(
    *,
    created_at: datetime,
    from_seq: int,
    to_seq: int,
    pruned_count: int,
    last_event_hash: Optional[str],
) -> dict[str, Any]:
    return {
        "created_at": created_at.isoformat(),
        "from_seq": int(from_seq),
        "to_seq": int(to_seq),
        "pruned_count": int(pruned_count),
        "last_event_hash": last_event_hash or "",
    }


def sign_checkpoint(payload: dict[str, Any], prev_hash: Optional[str]) -> str:
    return _digest(_stable_json({"checkpoint": payload, "prev_checkpoint_hash": prev_hash or ""}))


def locked_head(db: Session) -> AuditChainHeadModel:
    head = (
        db.query(AuditChainHeadModel)
        .filter(AuditChainHeadModel.id == CHAIN_HEAD_ID)
        .with_for_update()
        .first()
    )
    if head is not None:
        return head
    head = AuditChainHeadModel(id=CHAIN_HEAD_ID, seq=0, head_hash=None, chain_from_seq=1)
    db.add(head)
    db.flush()
    return head


def link_event(db: Session, row: AdminAuditEventModel) -> AdminAuditEventModel:
    head = locked_head(db)
    row.seq = int(head.seq or 0) + 1
    row.prev_event_hash = (head.head_hash or None)
    row.event_hash = sign_event(event_payload(row), row.prev_event_hash)
    head.seq = row.seq
    head.head_hash = row.event_hash
    head.updated_at = datetime.utcnow()
    db.add(head)
    return row


def chain_floor(db: Session) -> int:
    head = db.query(AuditChainHeadModel).filter(AuditChainHeadModel.id == CHAIN_HEAD_ID).first()
    return int(head.chain_from_seq or 1) if head is not None else 1


def latest_checkpoint(db: Session) -> Optional[AuditChainCheckpointModel]:
    return (
        db.query(AuditChainCheckpointModel)
        .order_by(AuditChainCheckpointModel.to_seq.desc())
        .first()
    )


def seal_pruned_range(
    db: Session,
    *,
    from_seq: int,
    to_seq: int,
    pruned_count: int,
    last_event_hash: Optional[str],
) -> AuditChainCheckpointModel:
    previous = latest_checkpoint(db)
    created_at = datetime.utcnow()
    payload = checkpoint_payload(
        created_at=created_at,
        from_seq=from_seq,
        to_seq=to_seq,
        pruned_count=pruned_count,
        last_event_hash=last_event_hash,
    )
    prev_hash = previous.checkpoint_hash if previous is not None else None
    row = AuditChainCheckpointModel(
        id=str(uuid.uuid4()),
        created_at=created_at,
        from_seq=from_seq,
        to_seq=to_seq,
        pruned_count=pruned_count,
        last_event_hash=last_event_hash,
        prev_checkpoint_hash=prev_hash,
        checkpoint_hash=sign_checkpoint(payload, prev_hash),
    )
    db.add(row)
    return row


def _predecessor_hash(db: Session, first: AdminAuditEventModel, floor: int) -> tuple[Optional[str], bool]:
    if int(first.seq) <= floor:
        return None, False
    previous = (
        db.query(AdminAuditEventModel)
        .filter(AdminAuditEventModel.seq == int(first.seq) - 1)
        .first()
    )
    if previous is not None:
        return (previous.event_hash or None), False
    checkpoint = (
        db.query(AuditChainCheckpointModel)
        .filter(AuditChainCheckpointModel.to_seq == int(first.seq) - 1)
        .first()
    )
    if checkpoint is not None:
        return (checkpoint.last_event_hash or None), False
    return None, True


def _page_rows(db: Session, *, after_seq: int, limit: int) -> Sequence[AdminAuditEventModel]:
    return (
        db.query(AdminAuditEventModel)
        .filter(AdminAuditEventModel.seq > after_seq)
        .order_by(AdminAuditEventModel.seq.asc())
        .limit(limit)
        .all()
    )


def verify_page(db: Session, *, after_seq: int, limit: int) -> ChainPage:
    floor = chain_floor(db)
    start = max(after_seq, floor - 1)
    rows = _page_rows(db, after_seq=start, limit=limit)
    if not rows:
        return ChainPage(checked=0, last_seq=start, breaks=(), exhausted=True)

    expected_prev, orphaned = _predecessor_hash(db, rows[0], floor)
    breaks: list[ChainBreak] = []
    if orphaned:
        breaks.append(
            ChainBreak(seq=int(rows[0].seq), event_id=rows[0].id, reason=BREAK_MISSING_PREDECESSOR)
        )
        expected_prev = rows[0].prev_event_hash or None

    expected_seq = int(rows[0].seq)
    for row in rows:
        seq = int(row.seq)
        if seq != expected_seq:
            breaks.append(ChainBreak(seq=seq, event_id=row.id, reason=BREAK_SEQ_GAP))
        if (row.prev_event_hash or None) != expected_prev:
            breaks.append(ChainBreak(seq=seq, event_id=row.id, reason=BREAK_PREV_HASH_MISMATCH))
        if sign_event(event_payload(row), row.prev_event_hash or None) != (row.event_hash or ""):
            breaks.append(ChainBreak(seq=seq, event_id=row.id, reason=BREAK_EVENT_HASH_MISMATCH))
        expected_prev = row.event_hash or None
        expected_seq = seq + 1

    return ChainPage(
        checked=len(rows),
        last_seq=int(rows[-1].seq),
        breaks=tuple(breaks),
        exhausted=len(rows) < limit,
    )
