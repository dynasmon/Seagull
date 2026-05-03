from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.core.db import engine
from app.core.observability import log_event
from app.features.attack_chain.worker_runtime import (
    AttackStage,
    CaseRow,
    StepCandidate,
    attack_story_maxspan_seconds,
    case_recent_step_exists,
    close_stale_cases,
    detect_steps,
    evaluate_candidate,
    evaluate_attack_stories,
    find_attachable_case_id,
    get_or_create_open_case_ex,
    insert_step_and_update_case,
)

from .repository import (
    _baseline_mark_login,
    _clear_ssh_failures,
    _get_recent_last_access,
    _inc_ssh_failure,
    _list_case_steps_since,
    _list_recent_alerts,
    _list_recent_correlation_incidents,
    _load_case_by_id,
    _open_case_exists,
    _upsert_last_access,
)
from .state import _fingerprint, _load_allowlist_rules, _load_attack_story_templates, _utc_now

logger = logging.getLogger("seagull.worker.attack_chain")


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
    stories, _story_errors = _load_attack_story_templates(ttl_seconds=30.0)
    story_lookback_seconds = attack_story_maxspan_seconds(stories)
    story_support_cache: Dict[tuple[int, str, str], Dict[str, List[Dict[str, Any]]]] = {}

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
                ev_ts = ev.get("timestamp")
                if not isinstance(ev_ts, datetime):
                    ev_ts = now

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
                        continue

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

                if not getattr(cand, "emit", True):
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
                story_eval = None
                story_bundle = None
                if stories and story_lookback_seconds > 0:
                    story_key = (int(case.id), agent_id, str(suspect_ip or ""))
                    story_bundle = story_support_cache.get(story_key)
                    if story_bundle is None:
                        since = now - timedelta(seconds=int(story_lookback_seconds))
                        story_bundle = {
                            "steps": _list_case_steps_since(conn, case_id=int(case.id), since=since, limit=256),
                            "alerts": _list_recent_alerts(conn, since=since, suspect_ip=suspect_ip, limit=256),
                            "incidents": _list_recent_correlation_incidents(
                                conn,
                                since=since,
                                suspect_ip=suspect_ip,
                                agent_id=agent_id,
                                limit=128,
                            ),
                        }
                        story_support_cache[story_key] = story_bundle

                    story_eval = evaluate_attack_stories(
                        stories=stories,
                        case_context=dict(case.context or {}),
                        existing_steps=story_bundle["steps"],
                        alerts=story_bundle["alerts"],
                        correlation_incidents=story_bundle["incidents"],
                        candidate=cand,
                        event=ev,
                        now=now,
                        entity_values={
                            "agent_id": agent_id,
                            "suspect_ip": str(suspect_ip or (case.context or {}).get("last_ssh_src_ip") or ""),
                        },
                        candidate_confidence=int(scored.confidence),
                    )
                    merged_context_patch.update(dict((story_eval.context_patch or {})))

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
                if story_eval and story_eval.detail_patch:
                    details.update(dict(story_eval.detail_patch))

                step_id, new_score, new_max_stage = insert_step_and_update_case(
                    conn,
                    case=case,
                    stage=cand.stage,
                    label=cand.title,
                    fingerprint=fp,
                    score_delta=int(scored.score_delta) + int((story_eval.score_delta if story_eval else 0) or 0),
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

                if story_bundle is not None:
                    story_bundle["steps"].append(
                        {
                            "id": int(step_id),
                            "stage": cand.stage.value,
                            "label": cand.title,
                            "event_type": ev.get("event_type"),
                            "timestamp": ev_ts,
                            "src_ip": ev.get("src_ip"),
                            "dst_ip": ev.get("dst_ip"),
                            "details": details,
                        }
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

        stats["cases_closed"] = int(
            close_stale_cases(conn, now=now, idle_close_seconds=cfg.case_idle_close_seconds) or 0
        )

    stats["cases_touched"] = len(touched_case_ids)
    return last_id, stats
