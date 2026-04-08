"""Attack Chain worker.

Polls net_events and converts low-level telemetry into scored, stateful cases.

This worker is intentionally independent from the ingest path to keep ingestion
fast and predictable under load.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import Index, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import OperationalError

from app.core.db import engine
from app.core.config import settings
from app.core.db_lifecycle import ensure_database_ready
from app.core.observability import log_event, setup_logging
from app.features.attack_chain.worker_runtime import (
    AttackChainAllowlistModel,
    AttackChainCaseModel,
    AttackChainLastAccessModel,
    AttackChainLoginBaselineModel,
    AttackChainSshFailureModel,
    AttackChainStepModel,
    AttackStage,
    CaseRow,
    StepCandidate,
    case_recent_step_exists,
    close_stale_cases,
    detect_steps,
    evaluate_candidate,
    find_attachable_case_id,
    get_or_create_open_case_ex,
    insert_step_and_update_case,
    load_config,
)
from app.features.events.worker_runtime import NetEventModel
from app.shared.indexing.models import SearchIndexOffsetModel


OFFSET_NAME = "attack_chain_v1"

setup_logging("worker-attack-chain")
logger = logging.getLogger("netwatch.worker.attack_chain")


_allowlist_cache: dict[str, Any] = {"loaded_at": 0.0, "rules": []}


def _load_allowlist_rules(*, ttl_seconds: float = 10.0) -> List[Dict[str, Any]]:
    """Load allowlist rules with a small TTL cache.

    The allowlist is expected to be tiny, but we still avoid querying on every batch.
    """

    now_t = time.time()
    loaded_at = float(_allowlist_cache.get("loaded_at") or 0.0)
    if ttl_seconds > 0 and (now_t - loaded_at) < ttl_seconds:
        return list(_allowlist_cache.get("rules") or [])

    try:
        with engine.begin() as conn:
            rows = conn.execute(
                select(
                    AttackChainAllowlistModel.id,
                    AttackChainAllowlistModel.rule_type,
                    AttackChainAllowlistModel.enabled,
                    AttackChainAllowlistModel.match_mode,
                    AttackChainAllowlistModel.pattern,
                    AttackChainAllowlistModel.agent_id,
                    AttackChainAllowlistModel.username,
                    AttackChainAllowlistModel.target_user,
                )
                .where(
                    AttackChainAllowlistModel.rule_type == "sudo_cmd",
                    AttackChainAllowlistModel.enabled.is_(True),
                )
                .order_by(AttackChainAllowlistModel.updated_at.desc(), AttackChainAllowlistModel.id.desc())
            ).mappings().all()
            rules = [dict(r) for r in rows]
    except Exception:
        rules = []

    _allowlist_cache["loaded_at"] = now_t
    _allowlist_cache["rules"] = rules
    return list(rules)


def _is_recent(ts: Optional[datetime], now: datetime, window_seconds: int) -> bool:
    if not ts or not isinstance(ts, datetime):
        return False
    if window_seconds <= 0:
        return False
    return ts >= (now - timedelta(seconds=int(window_seconds)))


def _ensure_bootstrap() -> None:
    """Ensure the minimal tables this worker depends on exist.

    In Docker Compose, workers may start before the API service. Existing NetWatch
    workers follow the same pattern to avoid noisy startup failures.
    """

    ensure_database_ready()
    with engine.begin() as conn:
        conn.execute(
            insert(SearchIndexOffsetModel)
            .values(name=OFFSET_NAME, last_id=0)
            .on_conflict_do_nothing(index_elements=[SearchIndexOffsetModel.name])
        )
        Index("idx_attack_chain_ssh_failures_last_seen", AttackChainSshFailureModel.last_seen_at.desc()).create(bind=conn, checkfirst=True)
        Index("idx_attack_chain_login_baseline_last_seen", AttackChainLoginBaselineModel.last_seen_at.desc()).create(bind=conn, checkfirst=True)
        Index("idx_attack_chain_last_access_accepted_at", AttackChainLastAccessModel.accepted_at.desc()).create(bind=conn, checkfirst=True)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fingerprint(stage: str, raw: str) -> str:
    base = f"{stage}:{raw}".encode("utf-8", errors="ignore")
    return hashlib.sha1(base).hexdigest()[:40]


def _get_last_id() -> int:
    with engine.begin() as conn:
        conn.execute(
            insert(SearchIndexOffsetModel)
            .values(name=OFFSET_NAME, last_id=0)
            .on_conflict_do_nothing(index_elements=[SearchIndexOffsetModel.name])
        )
        row = conn.execute(select(SearchIndexOffsetModel.last_id).where(SearchIndexOffsetModel.name == OFFSET_NAME).limit(1)).fetchone()
        return int(row[0]) if row and row[0] is not None else 0


def _set_last_id(last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(SearchIndexOffsetModel)
            .where(SearchIndexOffsetModel.name == OFFSET_NAME)
            .values(last_id=int(last_id), updated_at=func.now())
        )


def _fetch_events(after_id: int, limit: int) -> List[Dict[str, Any]]:
    # Keep the scan cheap by focusing only on event types that can feed the chain.
    event_types = [
        "ssh_auth",
        "sudo_cmd",
        # future-proof hooks
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
    """Upsert a (agent_id, username, src_ip) baseline row.

    Returns True if this is the first time we've seen this tuple.
    """

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
    """Increment SSH failure counter within a rolling window."""

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

    # Reset the counter if the window expired.
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


def _process_batch(events: List[Dict[str, Any]], cfg) -> tuple[int, Dict[str, Any]]:
    if not events:
        return 0, {
            "fetched": 0,
            "events_with_steps": 0,
            "candidates": 0,
            "inserted": 0,
            "dedup": 0,
            "cases_created": 0,
            "cases_attached": 0,
            "cases_touched": 0,
            "cases_closed": 0,
        }

    now = _utc_now()
    last_id = int(events[-1].get("id") or 0)

    # Cache attachable case per agent to keep local-step attribution cheap.
    attach_cache: Dict[str, Optional[int]] = {}

    stats = {
        "fetched": len(events),
        "events_with_steps": 0,
        "candidates": 0,
        "inserted": 0,
        "dedup": 0,
        "cases_created": 0,
        "cases_attached": 0,
        "cases_touched": 0,
        "cases_closed": 0,
    }

    touched_case_ids: set[int] = set()

    allowlist_rules = _load_allowlist_rules(ttl_seconds=10.0)

    with engine.begin() as conn:
        for ev in events:
            steps = detect_steps(ev, cfg, allowlist=allowlist_rules)
            if not steps:
                continue

            stats["events_with_steps"] += 1
            stats["candidates"] += len(steps)

            agent_id = str(ev.get("agent_id") or "").strip()
            if not agent_id:
                continue

            for cand in steps:
                # --- Correlation / noise suppression -----------------------
                # Many low-level events are context (accepted logins, routine sudo).
                # The worker decides when they become a visible step.

                ev_ts = ev.get("timestamp")
                if not isinstance(ev_ts, datetime):
                    ev_ts = now

                # SSH failures: track counts in a rolling window and emit only
                # when the threshold is reached (reduces case spam).
                if cand.kind == "ssh_fail":
                    ip = str(cand.suspect_ip or "").strip()
                    if not ip:
                        continue
                    username = str((cand.details or {}).get("username") or "")
                    c = _inc_ssh_failure(
                        conn,
                        agent_id=agent_id,
                        src_ip=ip,
                        username=username,
                        now=ev_ts,
                        window_seconds=int(getattr(cfg, "ssh_fail_window_seconds", 10 * 60)),
                    )

                    thr = int(getattr(cfg, "ssh_fail_threshold", 6))
                    if c < max(1, thr):
                        continue

                    # Promote to a real step only when the threshold is met.
                    cand = StepCandidate(
                        stage=AttackStage.initial_access,
                        title="SSH brute-force activity",
                        description=f"{c} authentication failures observed within a short window.",
                        score_delta=int(getattr(cfg, "ssh_bruteforce_score", 28)),
                        fingerprint=f"ssh_bruteforce:{ip}:{username}",
                        suspect_ip=ip,
                        details={"src_ip": ip, "username": username, "fail_count": c, "window_s": int(getattr(cfg, "ssh_fail_window_seconds", 10 * 60))},
                        kind="ssh_bruteforce",
                        technique_id="T1110.001",
                        confidence=85,
                        emit=True,
                    )

                # SSH accepts: update attribution baseline and emit only when
                # correlated (after failures) or coming from a new source.
                if cand.kind == "ssh_accept":
                    ip = str(cand.suspect_ip or "").strip()
                    username = str((cand.details or {}).get("username") or "")

                    if ip:
                        _upsert_last_access(conn, agent_id=agent_id, username=username, src_ip=ip, accepted_at=ev_ts)
                        first_time = _baseline_mark_login(conn, agent_id=agent_id, username=username, src_ip=ip, ts=ev_ts)
                    else:
                        first_time = False

                    if not ip:
                        continue

                    if _open_case_exists(conn, agent_id=agent_id, suspect_ip=ip):
                        # If a brute-force case is already open, this is a high-confidence success.
                        _clear_ssh_failures(conn, agent_id=agent_id, src_ip=ip, username=username)
                        cand = StepCandidate(
                            stage=AttackStage.initial_access,
                            title="SSH login accepted after failures",
                            description="Successful authentication after a burst of failures.",
                            score_delta=int(getattr(cfg, "ssh_bruteforce_success_score", 34)),
                            fingerprint=f"ssh_success_after_fail:{ip}:{username}",
                            suspect_ip=ip,
                            details={"src_ip": ip, "username": username, "reason": "success_after_failures"},
                            kind="ssh_bruteforce_success",
                            technique_id="T1078",
                            confidence=90,
                            emit=True,
                        )
                    elif first_time:
                        # New login source: medium confidence.
                        cand = StepCandidate(
                            stage=AttackStage.initial_access,
                            title="SSH login from new source",
                            description="First time this source IP was seen for this user/host.",
                            score_delta=int(getattr(cfg, "ssh_new_source_score", 14)),
                            fingerprint=f"ssh_new_source:{ip}:{username}",
                            suspect_ip=ip,
                            details={"src_ip": ip, "username": username, "reason": "new_source_ip"},
                            kind="ssh_new_source",
                            technique_id="T1078",
                            confidence=60,
                            emit=True,
                        )
                    else:
                        # Likely normal access (do not emit).
                        continue

                # Local activity (sudo/exec/persistence) can often be attributed
                # to a recent remote login. This improves narratives.
                suspect_ip = cand.suspect_ip
                if not suspect_ip:
                    la = _get_recent_last_access(
                        conn,
                        agent_id=agent_id,
                        now=now,
                        window_seconds=int(getattr(cfg, "attach_local_window_seconds", 20 * 60)),
                    )
                    if la and la.get("src_ip"):
                        suspect_ip = str(la.get("src_ip") or "").strip() or None

                # Routine sudo commands are suppressed unless they can be
                # attached to an already-open case.
                if not getattr(cand, "emit", True):
                    # Only emit suppressed candidates as context if we can
                    # attach them to an existing case.
                    can_attach = False
                    if suspect_ip and _open_case_exists(conn, agent_id=agent_id, suspect_ip=str(suspect_ip)):
                        can_attach = True
                    elif agent_id not in attach_cache:
                        attach_cache[agent_id] = find_attachable_case_id(
                            conn,
                            agent_id=agent_id,
                            now=now,
                            attach_window_seconds=cfg.attach_local_window_seconds,
                        )
                        can_attach = bool(attach_cache.get(agent_id))

                    if not can_attach:
                        continue

                    cand = StepCandidate(
                        stage=cand.stage,
                        title="Privileged command (context)",
                        description="Privileged activity recorded as context during an active case.",
                        score_delta=0,
                        fingerprint=f"ctx:{cand.fingerprint}",
                        suspect_ip=suspect_ip,
                        details=dict(cand.details or {}),
                        kind="context",
                        technique_id=cand.technique_id,
                        confidence=min(40, int(getattr(cand, "confidence", 20) or 20)),
                        emit=True,
                    )

                context_patch: Dict[str, Any] = {}
                if cand.kind in {"ssh_bruteforce_success", "ssh_new_source"} and suspect_ip:
                    context_patch["last_ssh_accept_at"] = ev_ts.isoformat()
                    context_patch["last_ssh_src_ip"] = str(suspect_ip)
                    context_patch["last_ssh_username"] = str((cand.details or {}).get("username") or "")

                case: Optional[CaseRow] = None
                if suspect_ip:
                    case, created = get_or_create_open_case_ex(
                        conn,
                        agent_id=agent_id,
                        suspect_ip=str(suspect_ip),
                        now=now,
                        context_patch=context_patch or None,
                    )
                    if created:
                        stats["cases_created"] += 1
                else:
                    if agent_id not in attach_cache:
                        attach_cache[agent_id] = find_attachable_case_id(
                            conn,
                            agent_id=agent_id,
                            now=now,
                            attach_window_seconds=cfg.attach_local_window_seconds,
                        )

                    attached_id = attach_cache.get(agent_id)
                    if attached_id:
                        case = _load_case_by_id(conn, attached_id)
                        if case is not None:
                            stats["cases_attached"] += 1

                    if case is None:
                        case, created = get_or_create_open_case_ex(
                            conn,
                            agent_id=agent_id,
                            suspect_ip=None,
                            now=now,
                            context_patch=context_patch or None,
                        )
                        if created:
                            stats["cases_created"] += 1

                fp = _fingerprint(cand.stage.value, cand.fingerprint)

                if case_recent_step_exists(
                    conn,
                    case_id=case.id,
                    fingerprint=fp,
                    now=now,
                    dedup_seconds=cfg.step_dedup_seconds,
                ):
                    stats["dedup"] += 1
                    continue

                scored = evaluate_candidate(
                    case_max_stage=str(case.max_stage or "initial_access"),
                    case_context=dict(case.context or {}),
                    candidate=cand,
                    event=ev,
                    now=now,
                    transition_window_seconds=int(getattr(cfg, "stage_transition_window_seconds", 90 * 60)),
                )

                merged_context_patch = dict(context_patch or {})
                merged_context_patch.update(dict(scored.context_patch or {}))

                details = dict(cand.details or {})
                details.setdefault("raw_fingerprint", cand.fingerprint)
                details.setdefault("kind", getattr(cand, "kind", "signal"))
                details.setdefault("technique_id", getattr(cand, "technique_id", None))
                details["confidence"] = int(scored.confidence)
                details["evidence_class"] = str(scored.evidence_class)
                details["evidence_nature"] = str(scored.evidence_nature)
                details["evidence_source"] = str(scored.evidence_source)
                details["evidence_families"] = list(scored.evidence_families or [])
                details["confidence_factors"] = list(scored.confidence_factors or [])
                details["missing_evidence"] = list(scored.missing_evidence or [])
                details["support_gain"] = float(scored.support_gain)
                details["stage_support_snapshot"] = dict(scored.stage_support_snapshot or {})
                details["transition"] = {
                    "allowed": bool(scored.transition_allowed),
                    "promoted": bool(scored.promote_stage),
                    "reason": str(scored.transition_reason or ""),
                }
                details.setdefault("description", getattr(cand, "description", ""))

                step_id, new_score, new_max_stage = insert_step_and_update_case(
                    conn,
                    case=case,
                    stage=cand.stage,
                    label=cand.title,
                    fingerprint=fp,
                    score_delta=int(scored.score_delta),
                    now=now,
                    max_score=cfg.max_score,
                    event=ev,
                    details=details,
                    context_patch=merged_context_patch or None,
                    promote_stage=bool(scored.promote_stage),
                )

                merged_case_context = dict(case.context or {})
                merged_case_context.update(merged_context_patch)
                case = CaseRow(
                    id=int(case.id),
                    score=int(new_score),
                    max_stage=str(new_max_stage),
                    step_count=int(case.step_count) + 1,
                    context=merged_case_context,
                )

                touched_case_ids.add(int(case.id))
                stats["inserted"] += 1

                if bool(getattr(cfg, "debug", False)):
                    ev_id = ev.get("id")
                    ev_type = str(ev.get("event_type") or "")
                    src_ip = str(ev.get("src_ip") or "")
                    dst_ip = str(ev.get("dst_ip") or "")
                    log_event(
                        logger,
                        "info",
                        "attack_chain_step",
                        case_id=case.id,
                        step_id=step_id,
                        stage=cand.stage.value,
                        score_delta=int(scored.score_delta or 0),
                        new_score=new_score,
                        max_stage=new_max_stage,
                        evidence_class=str(scored.evidence_class),
                        transition_promoted=bool(scored.promote_stage),
                        ev_id=ev_id,
                        ev_type=ev_type,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        title=cand.title,
                    )

        # Periodic stale-case closure keeps the UI clean and prevents infinite open cases.
        stats["cases_closed"] = int(
            close_stale_cases(conn, now=now, idle_close_seconds=cfg.case_idle_close_seconds) or 0
        )

    stats["cases_touched"] = len(touched_case_ids)

    return last_id, stats


def main() -> None:
    settings.validate_for_service("worker-attack-chain")
    cfg = load_config()

    # Keep worker startup robust even if the API service hasn't run yet.
    _ensure_bootstrap()

    # Backward-compatible config reads: older containers may have older AttackChainConfig fields.
    log_every_s = float(getattr(cfg, "log_every_seconds", 2.0))
    log_idle_every_s = float(getattr(cfg, "log_idle_every_seconds", 20.0))
    debug = bool(getattr(cfg, "debug", False))

    log_event(
        logger,
        "info",
        "attack_chain_start",
        batch_size=cfg.batch_size,
        every_s=cfg.every_seconds,
        idle_sleep_s=cfg.idle_sleep_seconds,
        dedup_s=cfg.step_dedup_seconds,
        attach_window_s=cfg.attach_local_window_seconds,
        idle_close_s=cfg.case_idle_close_seconds,
        transition_window_s=int(getattr(cfg, "stage_transition_window_seconds", 90 * 60)),
        max_score=cfg.max_score,
        log_every_s=log_every_s,
        log_idle_every_s=log_idle_every_s,
        debug=debug,
    )

    backoff = 1.0
    last_id = 0
    idle_sleep = float(cfg.idle_sleep_seconds)
    every = float(cfg.every_seconds)

    last_ok_log_t = 0.0
    last_idle_log_t = 0.0

    while True:
        try:
            if last_id == 0:
                last_id = _get_last_id()

            events = _fetch_events(last_id, int(cfg.batch_size))
            if not events:
                now_t = time.time()
                if log_idle_every_s > 0 and (now_t - last_idle_log_t) >= log_idle_every_s:
                    max_id = _get_max_event_id()
                    lag = max(0, int(max_id) - int(last_id))
                    log_event(
                        logger,
                        "info",
                        "attack_chain_idle",
                        last_id=last_id,
                        max_id=max_id,
                        lag=lag,
                        sleep_s=idle_sleep,
                    )
                    last_idle_log_t = now_t
                time.sleep(idle_sleep)
                continue

            t0 = time.time()
            new_last, stats = _process_batch(events, cfg)
            if new_last and new_last > last_id:
                last_id = new_last
                _set_last_id(last_id)

            took_ms = int((time.time() - t0) * 1000)

            now_t = time.time()
            if log_every_s <= 0 or (now_t - last_ok_log_t) >= log_every_s:
                max_id = _get_max_event_id()
                lag = max(0, int(max_id) - int(last_id))
                log_event(
                    logger,
                    "info",
                    "attack_chain_ok",
                    last_id=last_id,
                    max_id=max_id,
                    lag=lag,
                    fetched=stats.get("fetched"),
                    events_with_steps=stats.get("events_with_steps"),
                    candidates=stats.get("candidates"),
                    inserted=stats.get("inserted"),
                    dedup=stats.get("dedup"),
                    cases_created=stats.get("cases_created"),
                    cases_attached=stats.get("cases_attached"),
                    cases_touched=stats.get("cases_touched"),
                    cases_closed=stats.get("cases_closed"),
                    took_ms=took_ms,
                )
                last_ok_log_t = now_t

            # Throttle even under load to keep CPU predictable.
            if every > 0:
                time.sleep(every)

            backoff = 1.0
        except KeyboardInterrupt:
            raise
        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "attack_chain_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            # Fail-closed: do not spin on hard failures.
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "attack_chain_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
