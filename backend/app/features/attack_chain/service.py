from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.core.pagination import make_cursor_ts_id, parse_cursor_ts_id
from app.core.portal_auth import PortalPrincipal
from app.features.attack_chain import repository
from app.features.attack_chain.domain.reasoning import build_case_reasoning
from app.features.attack_chain.domain.types import stage_rank
from app.features.attack_chain.models import AttackChainAllowlistModel
from app.features.attack_chain.schemas import (
    AttackChainAllowlistCreate,
    AttackChainAllowlistUpdate,
    AttackChainCaseWithSteps,
)
from app.shared.schemas import CursorPage
from app.shared.taxonomy.catalog import technique_name
from app.shared.taxonomy.schemas import MitreCaseSummary, MitreTacticCoverage, MitreTechniqueStat

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


def _parse_since(since: Optional[str]) -> datetime | None:
    if not since:
        return None
    try:
        s = since.strip()
        if s.endswith("Z"):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


def list_cases(
    db: Session,
    *,
    page_size: int,
    cursor: Optional[str],
    agent_id: Optional[str],
    suspect_ip: Optional[str],
    status: Optional[str],
    min_score: Optional[int],
    since: Optional[str],
) -> CursorPage:
    cursor_parsed = parse_cursor_ts_id(cursor) if cursor else None
    rows = repository.list_cases_page(
        db,
        page_size=page_size,
        agent_id=agent_id,
        suspect_ip=suspect_ip,
        status=status,
        min_score=min_score,
        since_dt=_parse_since(since),
        cursor_parsed=cursor_parsed,
    )
    has_more = len(rows) > int(page_size)
    items = rows[: int(page_size)]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = make_cursor_ts_id(last.last_seen_at, last.id)
    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


def get_case(db: Session, *, case_id: int):
    row = repository.get_case(db, int(case_id))
    if not row:
        raise HTTPException(status_code=404, detail="Case not found")
    return row


def list_case_steps(db: Session, *, case_id: int):
    _ = get_case(db, case_id=case_id)
    return repository.list_steps_by_case(db, case_id=int(case_id))


def get_case_with_steps(db: Session, *, case_id: int) -> AttackChainCaseWithSteps:
    case = get_case(db, case_id=case_id)
    steps = repository.list_steps_by_case(db, case_id=int(case_id))

    stage_seen = []
    stage_set = set()
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
        stats = t_bucket.setdefault(tid, {"technique": tname, "count": 0, "max": 0, "sum": 0})
        stats["count"] += 1
        stats["max"] = max(stats["max"], conf_i)
        stats["sum"] += conf_i

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
    reasoning = build_case_reasoning(case=case, steps=steps)
    return {"case": case, "steps": steps, "mitre": mitre_summary, "reasoning": reasoning}


def close_case(
    db: Session,
    *,
    case_id: int,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> dict:
    case = repository.get_case(db, int(case_id))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if (case.status or "").lower() == "closed":
        return {"status": "ok", "case_id": case.id, "already_closed": True}

    before = {"id": case.id, "status": case.status, "closed_at": (case.closed_at.isoformat() if case.closed_at else None)}
    case.status = "closed"
    case.closed_at = case.closed_at or _utc_now()
    repository.save_case(db, case)
    audit_writer(
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
    repository.commit(db)
    return {"status": "ok", "case_id": case.id}


def list_allowlist(db: Session, *, rule_type: str):
    rt = (rule_type or "sudo_cmd").strip().lower()
    return repository.list_allowlist(db, rule_type=rt)


def _rule_snapshot(row: AttackChainAllowlistModel) -> dict:
    return {
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


def create_allowlist(
    db: Session,
    *,
    payload: AttackChainAllowlistCreate,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
):
    mode = _validate_allowlist_mode(payload.match_mode)
    pattern = (payload.pattern or "").strip()
    if not pattern:
        raise HTTPException(status_code=422, detail="pattern is required")
    row = repository.create_allowlist(
        db,
        rule_type="sudo_cmd",
        enabled=bool(payload.enabled),
        match_mode=mode,
        pattern=pattern[:512],
        agent_id=_norm_opt(payload.agent_id, max_len=64),
        username=_norm_opt(payload.username, max_len=128),
        target_user=_norm_opt(payload.target_user, max_len=128),
        notes=_norm_opt(payload.notes, max_len=256),
    )
    repository.flush(db)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="allowlist.create",
        resource_type="attack_chain_allowlist",
        resource_id=str(row.id),
        outcome="success",
        before={},
        after=_rule_snapshot(row),
    )
    repository.commit(db)
    repository.refresh(db, row)
    return row


def update_allowlist(
    db: Session,
    *,
    rule_id: int,
    payload: AttackChainAllowlistUpdate,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
):
    row = repository.get_allowlist_rule(db, int(rule_id))
    if not row:
        raise HTTPException(status_code=404, detail="Allowlist rule not found")
    before = _rule_snapshot(row)
    if payload.enabled is not None:
        row.enabled = bool(payload.enabled)
    if payload.match_mode is not None:
        row.match_mode = _validate_allowlist_mode(payload.match_mode)
    if payload.pattern is not None:
        p = (payload.pattern or "").strip()
        if not p:
            raise HTTPException(status_code=422, detail="pattern must not be empty")
        row.pattern = p[:512]
    if payload.agent_id is not None:
        row.agent_id = _norm_opt(payload.agent_id, max_len=64)
    if payload.username is not None:
        row.username = _norm_opt(payload.username, max_len=128)
    if payload.target_user is not None:
        row.target_user = _norm_opt(payload.target_user, max_len=128)
    if payload.notes is not None:
        row.notes = _norm_opt(payload.notes, max_len=256)

    repository.save_allowlist_rule(db, row)
    audit_writer(
        db,
        request=request,
        actor=audit_actor(admin.id, admin.username),
        event_type="admin_action",
        action="allowlist.update",
        resource_type="attack_chain_allowlist",
        resource_id=str(row.id),
        outcome="success",
        before=before,
        after=_rule_snapshot(row),
    )
    repository.commit(db)
    repository.refresh(db, row)
    return row


def delete_allowlist(
    db: Session,
    *,
    rule_id: int,
    request,
    admin: PortalPrincipal,
    audit_writer=write_audit_event,
) -> dict:
    row = repository.get_allowlist_rule(db, int(rule_id))
    if not row:
        raise HTTPException(status_code=404, detail="Allowlist rule not found")
    before = _rule_snapshot(row)
    repository.delete_allowlist_rule(db, row)
    audit_writer(
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
    repository.commit(db)
    return {"status": "ok", "deleted": True, "id": int(rule_id)}
