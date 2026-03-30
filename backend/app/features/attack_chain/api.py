from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, or_, select

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import PortalPrincipal, get_current_user, require_admin
from app.features.attack_chain.models import AttackChainAllowlistModel, AttackChainCaseModel, AttackChainStepModel
from app.features.attack_chain.schemas import (
    AttackChainAllowlistCreate,
    AttackChainAllowlistDB,
    AttackChainAllowlistUpdate,
    AttackChainCaseDB,
    AttackChainCaseWithSteps,
    AttackChainStepDB,
)
from app.shared.taxonomy.schemas import MitreCaseSummary, MitreTacticCoverage, MitreTechniqueStat
from app.shared.taxonomy.catalog import technique_name
from app.features.attack_chain.domain.types import stage_rank
from app.shared.schemas import CursorPage


router = APIRouter(
    prefix="/attack-chain",
    tags=["attack_chain"],
    dependencies=[Depends(get_current_user)],
)


_ALLOWLIST_MODES = {"exact", "prefix", "contains"}


def _norm_opt(v: Optional[str], *, max_len: int) -> Optional[str]:
    if v is None:
        return None
    s = v.strip()
    if not s:
        return None
    return s[:max_len]


def _validate_allowlist_mode(mode: str) -> str:
    m = (mode or "").strip().lower()
    if m not in _ALLOWLIST_MODES:
        raise HTTPException(status_code=422, detail=f"match_mode must be one of: {', '.join(sorted(_ALLOWLIST_MODES))}")
    return m


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
        # Build MITRE progression + coverage summary (MVP for reporting/heatmaps).
        # Note: attack-chain stages are already ATT&CK-aligned tactics.
        stage_seen = []
        stage_set = set()

        # tactic -> technique_id -> stats
        cov = {}

        for s in steps:
            st = str(getattr(s, "stage", "") or "").strip() or "unknown"
            if st not in stage_set:
                stage_set.add(st)
                stage_seen.append(st)

            d = getattr(s, "details", None)
            if not isinstance(d, dict):
                continue
            tid = str(d.get("technique_id") or "").strip()
            if not tid:
                continue
            conf = d.get("confidence")
            try:
                conf_i = int(conf)
            except Exception:
                conf_i = 0
            tname = str(d.get("technique") or "").strip() or (technique_name(tid) or None)

            t_bucket = cov.setdefault(st, {})
            stats = t_bucket.setdefault(
                tid,
                {"technique": tname, "count": 0, "max": 0, "sum": 0},
            )
            stats["count"] += 1
            stats["max"] = max(stats["max"], conf_i)
            stats["sum"] += conf_i

        # Sort progression by known stage rank
        stage_seen.sort(key=lambda x: stage_rank(x))

        tactics_out = []
        for tactic, per_tid in cov.items():
            techniques = []
            total = 0
            maxc = 0
            sumc = 0
            for tid, st in per_tid.items():
                cnt = int(st.get("count") or 0)
                if cnt <= 0:
                    continue
                total += cnt
                maxc = max(maxc, int(st.get("max") or 0))
                sumc += int(st.get("sum") or 0)
                techniques.append(
                    MitreTechniqueStat(
                        technique_id=tid,
                        technique=st.get("technique"),
                        count=cnt,
                        max_confidence=int(st.get("max") or 0),
                        avg_confidence=float((int(st.get("sum") or 0) / cnt) if cnt else 0.0),
                    )
                )

            techniques.sort(key=lambda x: (-int(x.count), x.technique_id))
            avgc = float((sumc / total) if total else 0.0)
            tactics_out.append(
                MitreTacticCoverage(
                    tactic=tactic,
                    total=int(total),
                    max_confidence=int(maxc),
                    avg_confidence=avgc,
                    techniques=techniques,
                )
            )

        tactics_out.sort(key=lambda x: (-int(x.total), x.tactic))

        mitre_summary = MitreCaseSummary(progression=stage_seen, tactics=tactics_out)

        return {"case": case, "steps": steps, "mitre": mitre_summary}
    finally:
        db.close()


@router.post("/cases/{case_id}/close")
def close_case(case_id: int, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        case = db.get(AttackChainCaseModel, int(case_id))
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        if (case.status or "").lower() == "closed":
            return {"status": "ok", "case_id": case.id, "already_closed": True}

        before = {"id": case.id, "status": case.status, "closed_at": (case.closed_at.isoformat() if case.closed_at else None)}
        case.status = "closed"
        case.closed_at = case.closed_at or _utc_now()
        db.add(case)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="attack_chain.case.close",
            resource_type="attack_chain_case",
            resource_id=str(case.id),
            outcome="success",
            before=before,
            after={"id": case.id, "status": case.status, "closed_at": case.closed_at.isoformat()},
        )
        db.commit()
        return {"status": "ok", "case_id": case.id}
    finally:
        db.close()


# ------------------------
# Allowlist (admin-only)
# ------------------------


@router.get("/allowlist", response_model=list[AttackChainAllowlistDB])
def list_allowlist(rule_type: str = Query("sudo_cmd", min_length=1, max_length=32), _: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        rt = (rule_type or "sudo_cmd").strip().lower()
        stmt = (
            select(AttackChainAllowlistModel)
            .where(AttackChainAllowlistModel.rule_type == rt)
            .order_by(AttackChainAllowlistModel.enabled.desc(), AttackChainAllowlistModel.updated_at.desc(), AttackChainAllowlistModel.id.desc())
        )
        return db.execute(stmt).scalars().all()
    finally:
        db.close()


@router.post("/allowlist", response_model=AttackChainAllowlistDB)
def create_allowlist(payload: AttackChainAllowlistCreate, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        mode = _validate_allowlist_mode(payload.match_mode)
        pattern = (payload.pattern or "").strip()
        if not pattern:
            raise HTTPException(status_code=422, detail="pattern is required")

        row = AttackChainAllowlistModel(
            rule_type="sudo_cmd",
            enabled=bool(payload.enabled),
            match_mode=mode,
            pattern=pattern[:512],
            agent_id=_norm_opt(payload.agent_id, max_len=64),
            username=_norm_opt(payload.username, max_len=128),
            target_user=_norm_opt(payload.target_user, max_len=128),
            notes=_norm_opt(payload.notes, max_len=256),
        )
        db.add(row)
        db.flush()
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="allowlist.create",
            resource_type="attack_chain_allowlist",
            resource_id=str(row.id),
            outcome="success",
            before={},
            after={
                "id": row.id,
                "rule_type": row.rule_type,
                "enabled": bool(row.enabled),
                "match_mode": row.match_mode,
                "pattern": row.pattern,
                "agent_id": row.agent_id,
                "username": row.username,
                "target_user": row.target_user,
                "notes": row.notes,
            },
        )
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()


@router.put("/allowlist/{rule_id}", response_model=AttackChainAllowlistDB)
def update_allowlist(rule_id: int, payload: AttackChainAllowlistUpdate, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row = db.get(AttackChainAllowlistModel, int(rule_id))
        if not row:
            raise HTTPException(status_code=404, detail="Allowlist rule not found")

        before = {
            "id": row.id,
            "rule_type": row.rule_type,
            "enabled": bool(row.enabled),
            "match_mode": row.match_mode,
            "pattern": row.pattern,
            "agent_id": row.agent_id,
            "username": row.username,
            "target_user": row.target_user,
            "notes": row.notes,
        }
        if payload.enabled is not None:
            row.enabled = bool(payload.enabled)
        if payload.match_mode is not None:
            row.match_mode = _validate_allowlist_mode(payload.match_mode)
        if payload.pattern is not None:
            p = (payload.pattern or "").strip()
            if not p:
                raise HTTPException(status_code=422, detail="pattern must not be empty")
            row.pattern = p[:512]

        # Optional scope fields: empty string clears.
        if payload.agent_id is not None:
            row.agent_id = _norm_opt(payload.agent_id, max_len=64)
        if payload.username is not None:
            row.username = _norm_opt(payload.username, max_len=128)
        if payload.target_user is not None:
            row.target_user = _norm_opt(payload.target_user, max_len=128)
        if payload.notes is not None:
            row.notes = _norm_opt(payload.notes, max_len=256)

        db.add(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="allowlist.update",
            resource_type="attack_chain_allowlist",
            resource_id=str(row.id),
            outcome="success",
            before=before,
            after={
                "id": row.id,
                "rule_type": row.rule_type,
                "enabled": bool(row.enabled),
                "match_mode": row.match_mode,
                "pattern": row.pattern,
                "agent_id": row.agent_id,
                "username": row.username,
                "target_user": row.target_user,
                "notes": row.notes,
            },
        )
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()


@router.delete("/allowlist/{rule_id}")
def delete_allowlist(rule_id: int, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        row = db.get(AttackChainAllowlistModel, int(rule_id))
        if not row:
            raise HTTPException(status_code=404, detail="Allowlist rule not found")
        before = {
            "id": row.id,
            "rule_type": row.rule_type,
            "enabled": bool(row.enabled),
            "match_mode": row.match_mode,
            "pattern": row.pattern,
            "agent_id": row.agent_id,
            "username": row.username,
            "target_user": row.target_user,
            "notes": row.notes,
        }
        db.delete(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="allowlist.delete",
            resource_type="attack_chain_allowlist",
            resource_id=str(rule_id),
            outcome="success",
            before=before,
            after={},
        )
        db.commit()
        return {"status": "ok", "deleted": True, "id": int(rule_id)}
    finally:
        db.close()
