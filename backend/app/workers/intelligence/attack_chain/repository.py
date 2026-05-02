from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import Index, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert

from app.core.db import engine
from app.core.db.lifecycle import ensure_database_ready
from app.features.attack_chain.worker_runtime import (
    AttackChainCaseModel,
    AttackChainLastAccessModel,
    AttackChainLoginBaselineModel,
    AttackChainSshFailureModel,
    CaseRow,
)
from app.features.events.worker_runtime import NetEventModel
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset

from .state import _utc_now

OFFSET_NAME = "attack_chain_v1"


def _ensure_bootstrap() -> None:
    ensure_database_ready()
    with engine.begin() as conn:
        ensure_offset(OFFSET_NAME, conn=conn)
        Index("idx_attack_chain_ssh_failures_last_seen", AttackChainSshFailureModel.last_seen_at.desc()).create(bind=conn, checkfirst=True)
        Index("idx_attack_chain_login_baseline_last_seen", AttackChainLoginBaselineModel.last_seen_at.desc()).create(bind=conn, checkfirst=True)
        Index("idx_attack_chain_last_access_accepted_at", AttackChainLastAccessModel.accepted_at.desc()).create(bind=conn, checkfirst=True)


def _get_last_id() -> int:
    ensure_offset(OFFSET_NAME)
    return get_offset(OFFSET_NAME)


def _set_last_id(last_id: int) -> None:
    set_offset(OFFSET_NAME, last_id)


def _fetch_events(after_id: int, limit: int) -> List[Dict[str, Any]]:
    event_types = [
        "ssh_auth",
        "sudo_cmd",
        "ebpf_exec",
        "proc_exec",
        "fim_change",
        "persistence_systemd",
        "persistence_cron",
        "ssh_key_change",
        "beacon_suspect",
        "c2_suspect",
        "exfil_suspect",
        "egress_anomaly",
    ]

    with engine.begin() as conn:
        rows = conn.execute(
            select(
                NetEventModel.id,
                NetEventModel.agent_id,
                NetEventModel.event_type,
                NetEventModel.schema_version,
                NetEventModel.timestamp,
                NetEventModel.src_ip,
                NetEventModel.dst_ip,
                NetEventModel.src_port,
                NetEventModel.dst_port,
                NetEventModel.proto,
                NetEventModel.bytes,
                NetEventModel.extra,
            )
            .where(NetEventModel.id > int(after_id), NetEventModel.event_type.in_(event_types))
            .order_by(NetEventModel.id.asc())
            .limit(int(limit))
        ).mappings().all()
        return [dict(r) for r in rows]


def _open_case_exists(conn, *, agent_id: str, suspect_ip: str) -> bool:
    row = conn.execute(
        select(AttackChainCaseModel.id)
        .where(
            AttackChainCaseModel.agent_id == agent_id,
            AttackChainCaseModel.suspect_ip == suspect_ip,
            AttackChainCaseModel.status == "open",
        )
        .limit(1)
    ).fetchone()
    return row is not None


def _upsert_last_access(conn, *, agent_id: str, username: str, src_ip: str, accepted_at: datetime) -> None:
    conn.execute(
        insert(AttackChainLastAccessModel)
        .values(agent_id=agent_id, username=username or None, src_ip=src_ip or None, accepted_at=accepted_at)
        .on_conflict_do_update(
            index_elements=[AttackChainLastAccessModel.agent_id],
            set_={
                "username": username or None,
                "src_ip": src_ip or None,
                "accepted_at": accepted_at,
            },
        )
    )


def _get_recent_last_access(conn, *, agent_id: str, now: datetime, window_seconds: int) -> Optional[Dict[str, Any]]:
    if window_seconds <= 0:
        return None
    row = conn.execute(
        select(
            AttackChainLastAccessModel.username,
            AttackChainLastAccessModel.src_ip,
            AttackChainLastAccessModel.accepted_at,
        )
        .where(AttackChainLastAccessModel.agent_id == agent_id)
        .limit(1)
    ).mappings().fetchone()
    if not row:
        return None
    accepted_at = row.get("accepted_at")
    if not isinstance(accepted_at, datetime):
        return None
    if accepted_at < (now - timedelta(seconds=int(window_seconds))):
        return None
    return {"username": str(row.get("username") or ""), "src_ip": str(row.get("src_ip") or ""), "accepted_at": accepted_at}


def _baseline_mark_login(conn, *, agent_id: str, username: str, src_ip: str, ts: datetime) -> bool:
    row = conn.execute(
        select(AttackChainLoginBaselineModel.seen_count)
        .where(
            AttackChainLoginBaselineModel.agent_id == agent_id,
            AttackChainLoginBaselineModel.username == (username or ""),
            AttackChainLoginBaselineModel.src_ip == src_ip,
        )
        .limit(1)
    ).fetchone()
    first_time = row is None

    conn.execute(
        insert(AttackChainLoginBaselineModel)
        .values(
            agent_id=agent_id,
            username=username or "",
            src_ip=src_ip,
            first_seen_at=ts,
            last_seen_at=ts,
            seen_count=1,
        )
        .on_conflict_do_update(
            index_elements=[
                AttackChainLoginBaselineModel.agent_id,
                AttackChainLoginBaselineModel.username,
                AttackChainLoginBaselineModel.src_ip,
            ],
            set_={
                "last_seen_at": ts,
                "seen_count": AttackChainLoginBaselineModel.seen_count + 1,
            },
        )
    )

    return first_time


def _inc_ssh_failure(conn, *, agent_id: str, src_ip: str, username: str, now: datetime, window_seconds: int) -> int:
    if window_seconds <= 0:
        window_seconds = 10 * 60

    row = conn.execute(
        select(
            AttackChainSshFailureModel.first_seen_at,
            AttackChainSshFailureModel.last_seen_at,
            AttackChainSshFailureModel.fail_count,
        )
        .where(
            AttackChainSshFailureModel.agent_id == agent_id,
            AttackChainSshFailureModel.src_ip == src_ip,
            AttackChainSshFailureModel.username == (username or ""),
        )
        .limit(1)
    ).mappings().fetchone()

    if not row:
        conn.execute(
            insert(AttackChainSshFailureModel)
            .values(
                agent_id=agent_id,
                src_ip=src_ip,
                username=username or "",
                first_seen_at=now,
                last_seen_at=now,
                fail_count=1,
            )
            .on_conflict_do_update(
                index_elements=[
                    AttackChainSshFailureModel.agent_id,
                    AttackChainSshFailureModel.src_ip,
                    AttackChainSshFailureModel.username,
                ],
                set_={
                    "last_seen_at": now,
                    "fail_count": AttackChainSshFailureModel.fail_count + 1,
                },
            )
        )
        return 1

    first_seen_at = row.get("first_seen_at")
    last_seen_at = row.get("last_seen_at")
    fail_count = int(row.get("fail_count") or 0)
    if not isinstance(first_seen_at, datetime) or not isinstance(last_seen_at, datetime):
        first_seen_at = now
        last_seen_at = now
        fail_count = 0

    if last_seen_at < (now - timedelta(seconds=int(window_seconds))):
        conn.execute(
            update(AttackChainSshFailureModel)
            .where(
                AttackChainSshFailureModel.agent_id == agent_id,
                AttackChainSshFailureModel.src_ip == src_ip,
                AttackChainSshFailureModel.username == (username or ""),
            )
            .values(first_seen_at=now, last_seen_at=now, fail_count=1)
        )
        return 1

    new_count = fail_count + 1
    conn.execute(
        update(AttackChainSshFailureModel)
        .where(
            AttackChainSshFailureModel.agent_id == agent_id,
            AttackChainSshFailureModel.src_ip == src_ip,
            AttackChainSshFailureModel.username == (username or ""),
        )
        .values(last_seen_at=now, fail_count=int(new_count))
    )
    return int(new_count)


def _clear_ssh_failures(conn, *, agent_id: str, src_ip: str, username: str) -> None:
    conn.execute(
        delete(AttackChainSshFailureModel).where(
            AttackChainSshFailureModel.agent_id == agent_id,
            AttackChainSshFailureModel.src_ip == src_ip,
            AttackChainSshFailureModel.username == (username or ""),
        )
    )


def _get_max_event_id() -> int:
    with engine.begin() as conn:
        row = conn.execute(select(func.coalesce(func.max(NetEventModel.id), 0))).fetchone()
        try:
            return int(row[0] or 0)
        except Exception:
            return 0


def _load_case_by_id(conn, case_id: int) -> Optional[CaseRow]:
    row = conn.execute(
        select(
            AttackChainCaseModel.id,
            AttackChainCaseModel.score,
            AttackChainCaseModel.max_stage,
            AttackChainCaseModel.step_count,
            AttackChainCaseModel.context,
        ).where(AttackChainCaseModel.id == int(case_id))
    ).mappings().fetchone()
    if not row:
        return None
    ctx = row.get("context") if isinstance(row.get("context"), dict) else {}
    return CaseRow(
        id=int(row["id"]),
        score=int(row.get("score") or 0),
        max_stage=str(row.get("max_stage") or "initial_access"),
        step_count=int(row.get("step_count") or 0),
        context=ctx,
    )
