from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import and_, func, insert, or_, select, update

from app.features.attack_chain.domain.types import AttackStage, stage_rank
from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel


@dataclass(frozen=True)
class CaseRow:
    id: int
    score: int
    max_stage: str
    step_count: int
    context: Dict[str, Any]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_dict(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return v
    return {}


def get_or_create_open_case(
    conn,
    *,
    agent_id: str,
    suspect_ip: Optional[str],
    now: datetime,
    context_patch: Optional[Dict[str, Any]] = None,
) -> CaseRow:
    """Fetch an open case for (agent_id, suspect_ip) or create a new one."""

    case, _created = get_or_create_open_case_ex(
        conn,
        agent_id=agent_id,
        suspect_ip=suspect_ip,
        now=now,
        context_patch=context_patch,
    )
    return case


def get_or_create_open_case_ex(
    conn,
    *,
    agent_id: str,
    suspect_ip: Optional[str],
    now: datetime,
    context_patch: Optional[Dict[str, Any]] = None,
) -> Tuple[CaseRow, bool]:
    """Same as get_or_create_open_case, but returns (case, created)."""

    row = conn.execute(
        select(
            AttackChainCaseModel.id,
            AttackChainCaseModel.score,
            AttackChainCaseModel.max_stage,
            AttackChainCaseModel.step_count,
            AttackChainCaseModel.context,
        )
        .where(
            AttackChainCaseModel.agent_id == agent_id,
            AttackChainCaseModel.status == "open",
            or_(
                and_(suspect_ip is None, AttackChainCaseModel.suspect_ip.is_(None)),
                AttackChainCaseModel.suspect_ip == suspect_ip,
            ),
        )
        .order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
        .limit(1)
    ).mappings().fetchone()

    if row:
        ctx = _safe_dict(row.get("context"))
        if context_patch:
            ctx.update(_safe_dict(context_patch))
            conn.execute(
                update(AttackChainCaseModel)
                .where(AttackChainCaseModel.id == int(row["id"]))
                .values(context=ctx),
            )

        return (
            CaseRow(
                id=int(row["id"]),
                score=int(row.get("score") or 0),
                max_stage=str(row.get("max_stage") or "initial_access"),
                step_count=int(row.get("step_count") or 0),
                context=ctx,
            ),
            False,
        )

    ctx = _safe_dict(context_patch)
    inserted = conn.execute(
        insert(AttackChainCaseModel)
        .values(
            agent_id=agent_id,
            suspect_ip=suspect_ip,
            status="open",
            score=0,
            max_stage="initial_access",
            first_seen_at=now,
            last_seen_at=now,
            step_count=0,
            context=ctx,
        )
        .returning(AttackChainCaseModel.id)
    ).fetchone()

    case_id = int(inserted[0])
    return CaseRow(id=case_id, score=0, max_stage="initial_access", step_count=0, context=ctx), True


def case_recent_step_exists(
    conn,
    *,
    case_id: int,
    fingerprint: str,
    now: datetime,
    dedup_seconds: int,
) -> bool:
    if dedup_seconds <= 0:
        return False

    row = conn.execute(
        select(AttackChainStepModel.id)
        .where(
            AttackChainStepModel.case_id == int(case_id),
            AttackChainStepModel.fingerprint == str(fingerprint),
            AttackChainStepModel.created_at >= (now - timedelta(seconds=int(dedup_seconds))),
        )
        .limit(1)
    ).fetchone()

    return row is not None


def insert_step_and_update_case(
    conn,
    *,
    case: CaseRow,
    stage: AttackStage,
    label: str,
    fingerprint: str,
    score_delta: int,
    now: datetime,
    max_score: int,
    event: Dict[str, Any],
    details: Optional[Dict[str, Any]] = None,
    context_patch: Optional[Dict[str, Any]] = None,
) -> Tuple[int, int, str]:
    """Insert a step and update case aggregates.

    Returns (step_id, new_case_score, new_max_stage).
    """

    score_delta = int(score_delta or 0)
    new_score = max(0, int(case.score) + score_delta)
    if max_score > 0:
        new_score = min(new_score, int(max_score))

    old_stage = str(case.max_stage or "initial_access")
    new_max_stage = old_stage
    if stage_rank(stage.value) > stage_rank(old_stage):
        new_max_stage = stage.value

    ev_id = event.get("id")
    try:
        ev_id = int(ev_id) if ev_id is not None else None
    except Exception:
        ev_id = None

    ev_type = event.get("event_type")
    ts = event.get("timestamp")
    if not isinstance(ts, datetime):
        ts = now

    src_port = event.get("src_port")
    dst_port = event.get("dst_port")
    try:
        src_port = int(src_port) if src_port is not None else None
    except Exception:
        src_port = None
    try:
        dst_port = int(dst_port) if dst_port is not None else None
    except Exception:
        dst_port = None

    details = details or {}
    if not isinstance(details, dict):
        details = {}

    step_row = conn.execute(
        insert(AttackChainStepModel)
        .values(
            case_id=int(case.id),
            stage=stage.value,
            label=str(label),
            score_delta=int(score_delta),
            fingerprint=str(fingerprint)[:192],
            event_id=ev_id,
            event_type=str(ev_type or "")[:32] if ev_type else None,
            timestamp=ts,
            created_at=now,
            src_ip=(event.get("src_ip") or None),
            dst_ip=(event.get("dst_ip") or None),
            src_port=src_port,
            dst_port=dst_port,
            proto=(event.get("proto") or None),
            details=details,
        )
        .returning(AttackChainStepModel.id)
    ).fetchone()
    step_id = int(step_row[0])

    # Update case aggregate state.
    ctx = dict(case.context or {})
    if context_patch and isinstance(context_patch, dict):
        ctx.update(context_patch)

    conn.execute(
        update(AttackChainCaseModel)
        .where(AttackChainCaseModel.id == int(case.id))
        .values(
            score=int(new_score),
            max_stage=str(new_max_stage),
            last_seen_at=func.greatest(AttackChainCaseModel.last_seen_at, ts),
            step_count=AttackChainCaseModel.step_count + 1,
            context=ctx,
        )
    )

    return step_id, new_score, new_max_stage


def close_stale_cases(conn, *, now: datetime, idle_close_seconds: int) -> int:
    if idle_close_seconds <= 0:
        return 0

    res = conn.execute(
        update(AttackChainCaseModel)
        .where(
            AttackChainCaseModel.status == "open",
            AttackChainCaseModel.last_seen_at < (now - timedelta(seconds=int(idle_close_seconds))),
        )
        .values(
            status="closed",
            closed_at=func.coalesce(AttackChainCaseModel.closed_at, now),
        )
    )

    try:
        return int(res.rowcount or 0)
    except Exception:
        return 0


def find_attachable_case_id(conn, *, agent_id: str, now: datetime, attach_window_seconds: int) -> Optional[int]:
    """Find the best open case to attach local-only steps.

    This is used for post-access local activity (sudo/exec/persistence) when
    the originating remote IP cannot be directly inferred.
    """

    if attach_window_seconds <= 0:
        return None

    row = conn.execute(
        select(AttackChainCaseModel.id)
        .where(
            AttackChainCaseModel.agent_id == agent_id,
            AttackChainCaseModel.status == "open",
            AttackChainCaseModel.last_seen_at >= (now - timedelta(seconds=int(attach_window_seconds))),
        )
        .order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())
        .limit(1)
    ).fetchone()

    if not row:
        return None
    try:
        return int(row[0])
    except Exception:
        return None
