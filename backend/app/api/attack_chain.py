from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select

from app.core.db import SessionLocal
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import get_current_user, require_admin
from app.models.attack_chain import AttackChainCaseModel, AttackChainStepModel
from app.schemas.attack_chain import AttackChainCaseDB, AttackChainCaseWithSteps, AttackChainStepDB
from app.schemas.pagination import CursorPage


router = APIRouter(
    prefix="/attack-chain",
    tags=["attack_chain"],
    dependencies=[Depends(get_current_user)],
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/cases", response_model=CursorPage[AttackChainCaseDB])
def list_cases(
    page_size: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Opaque cursor from a previous call"),
    agent_id: Optional[str] = Query(None, min_length=1, max_length=64),
    suspect_ip: Optional[str] = Query(None, min_length=1, max_length=45),
    status: Optional[str] = Query(None, description="open | closed"),
    min_score: Optional[int] = Query(None, ge=0, le=1000),
    since: Optional[str] = Query(None, description="ISO timestamp (filters by last_seen_at)"),
):
    db = SessionLocal()
    try:
        stmt = select(AttackChainCaseModel).order_by(AttackChainCaseModel.last_seen_at.desc(), AttackChainCaseModel.id.desc())

        if agent_id:
            stmt = stmt.where(AttackChainCaseModel.agent_id == agent_id)
        if suspect_ip:
            stmt = stmt.where(AttackChainCaseModel.suspect_ip == suspect_ip)
        if status:
            stmt = stmt.where(AttackChainCaseModel.status == status)
        if min_score is not None:
            stmt = stmt.where(AttackChainCaseModel.score >= int(min_score))

        if since:
            try:
                s = since.strip()
                if s.endswith("Z"):
                    dt = datetime.fromisoformat(s[:-1] + "+00:00")
                else:
                    dt = datetime.fromisoformat(s)
                stmt = stmt.where(AttackChainCaseModel.last_seen_at >= dt)
            except Exception:
                pass

        if cursor:
            c_ts, c_id = parse_cursor_ts_id(cursor)
            stmt = stmt.where(
                or_(
                    AttackChainCaseModel.last_seen_at < c_ts,
                    and_(AttackChainCaseModel.last_seen_at == c_ts, AttackChainCaseModel.id < c_id),
                )
            )

        rows = db.execute(stmt.limit(int(page_size) + 1)).scalars().all()
        has_more = len(rows) > int(page_size)
        items = rows[: int(page_size)]

        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = make_cursor_ts_id(last.last_seen_at, last.id)

        return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)
    finally:
        db.close()


@router.get("/cases/{case_id}", response_model=AttackChainCaseDB)
def get_case(case_id: int):
    db = SessionLocal()
    try:
        row = db.get(AttackChainCaseModel, int(case_id))
        if not row:
            raise HTTPException(status_code=404, detail="Case not found")
        return row
    finally:
        db.close()


@router.get("/cases/{case_id}/steps", response_model=list[AttackChainStepDB])
def list_case_steps(case_id: int):
    db = SessionLocal()
    try:
        case = db.get(AttackChainCaseModel, int(case_id))
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        stmt = (
            select(AttackChainStepModel)
            .where(AttackChainStepModel.case_id == int(case_id))
            .order_by(AttackChainStepModel.timestamp.asc(), AttackChainStepModel.id.asc())
        )
        return db.execute(stmt).scalars().all()
    finally:
        db.close()


@router.get("/cases/{case_id}/full", response_model=AttackChainCaseWithSteps)
def get_case_with_steps(case_id: int):
    db = SessionLocal()
    try:
        case = db.get(AttackChainCaseModel, int(case_id))
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        steps = (
            db.execute(
                select(AttackChainStepModel)
                .where(AttackChainStepModel.case_id == int(case_id))
                .order_by(AttackChainStepModel.timestamp.asc(), AttackChainStepModel.id.asc())
            )
            .scalars()
            .all()
        )
        return {"case": case, "steps": steps}
    finally:
        db.close()


@router.post("/cases/{case_id}/close", dependencies=[Depends(require_admin)])
def close_case(case_id: int):
    db = SessionLocal()
    try:
        case = db.get(AttackChainCaseModel, int(case_id))
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        if (case.status or "").lower() == "closed":
            return {"status": "ok", "case_id": case.id, "already_closed": True}

        case.status = "closed"
        case.closed_at = case.closed_at or _utc_now()
        db.add(case)
        db.commit()
        return {"status": "ok", "case_id": case.id}
    finally:
        db.close()
