"""Attack Chain worker.

Polls net_events and converts low-level telemetry into scored, stateful cases.

This worker is intentionally independent from the ingest path to keep ingestion
fast and predictable under load.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.attack_chain.config import load_config
from app.attack_chain.detectors import detect_steps
from app.attack_chain.store import (
    CaseRow,
    close_stale_cases,
    find_attachable_case_id,
    get_or_create_open_case_ex,
    insert_step_and_update_case,
    case_recent_step_exists,
)
from app.attack_chain.types import AttackStage
from app.core.db import engine


OFFSET_NAME = "attack_chain_v1"


def _ensure_bootstrap() -> None:
    """Ensure the minimal tables this worker depends on exist.

    In Docker Compose, workers may start before the API service. Existing NetWatch
    workers follow the same pattern to avoid noisy startup failures.
    """

    with engine.begin() as conn:
        # Generic offsets table used by multiple workers.
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS search_index_offsets (
                    name TEXT PRIMARY KEY,
                    last_id INTEGER NOT NULL DEFAULT 0,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
        )

        # Stateful attack-chain case.
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS attack_chain_cases (
                    id SERIAL PRIMARY KEY,
                    agent_id VARCHAR(64) NOT NULL,
                    suspect_ip VARCHAR(45) NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'open',
                    score INTEGER NOT NULL DEFAULT 0,
                    max_stage VARCHAR(32) NOT NULL DEFAULT 'initial_access',
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    closed_at TIMESTAMPTZ NULL,
                    step_count INTEGER NOT NULL DEFAULT 0,
                    context JSONB NOT NULL DEFAULT '{}'::jsonb
                );
                """
            )
        )

        # Timeline steps.
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS attack_chain_steps (
                    id SERIAL PRIMARY KEY,
                    case_id INTEGER NOT NULL REFERENCES attack_chain_cases(id) ON DELETE CASCADE,
                    stage VARCHAR(32) NOT NULL,
                    label VARCHAR(96) NOT NULL,
                    score_delta INTEGER NOT NULL DEFAULT 0,
                    fingerprint VARCHAR(192) NOT NULL,
                    event_id INTEGER NULL REFERENCES net_events(id) ON DELETE SET NULL,
                    event_type VARCHAR(32) NULL,
                    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    src_ip VARCHAR(45) NULL,
                    dst_ip VARCHAR(45) NULL,
                    src_port INTEGER NULL,
                    dst_port INTEGER NULL,
                    proto VARCHAR(16) NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb
                );
                """
            )
        )

        # Indexes (keep consistent with schema_bootstrap).
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_chain_cases_agent_status_last_seen
                    ON attack_chain_cases (agent_id, status, last_seen_at DESC, id DESC);
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_chain_cases_suspect_last_seen
                    ON attack_chain_cases (suspect_ip, last_seen_at DESC, id DESC);
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_chain_open_case
                    ON attack_chain_cases (agent_id, COALESCE(suspect_ip, ''))
                    WHERE status = 'open';
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_chain_steps_case_time
                    ON attack_chain_steps (case_id, timestamp ASC, id ASC);
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_chain_steps_case_fp_created
                    ON attack_chain_steps (case_id, fingerprint, created_at DESC);
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_chain_steps_stage_time
                    ON attack_chain_steps (stage, timestamp DESC, id DESC);
                """
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS gin_attack_chain_cases_context ON attack_chain_cases USING GIN (context);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS gin_attack_chain_steps_details ON attack_chain_steps USING GIN (details);"))

        # Ensure offset row.
        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets (name, last_id)
                VALUES (:name, 0)
                ON CONFLICT (name) DO NOTHING;
                """
            ),
            {"name": OFFSET_NAME},
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _fingerprint(stage: str, raw: str) -> str:
    base = f"{stage}:{raw}".encode("utf-8", errors="ignore")
    return hashlib.sha1(base).hexdigest()[:40]


def _get_last_id() -> int:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets (name, last_id)
                VALUES (:name, 0)
                ON CONFLICT (name) DO NOTHING;
                """
            ),
            {"name": OFFSET_NAME},
        )
        row = conn.execute(text("SELECT last_id FROM search_index_offsets WHERE name=:name"), {"name": OFFSET_NAME}).fetchone()
        return int(row[0]) if row and row[0] is not None else 0


def _set_last_id(last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE search_index_offsets
                   SET last_id = :last_id,
                       updated_at = now()
                 WHERE name = :name;
                """
            ),
            {"name": OFFSET_NAME, "last_id": int(last_id)},
        )


def _fetch_events(after_id: int, limit: int) -> List[Dict[str, Any]]:
    # Keep the scan cheap by focusing only on event types that can feed the chain.
    sql = text(
        """
        SELECT
          id, agent_id, event_type, schema_version, timestamp,
          src_ip, dst_ip, src_port, dst_port, proto, bytes, extra
        FROM net_events
        WHERE id > :after_id
          AND event_type = ANY(:event_types)
        ORDER BY id ASC
        LIMIT :limit;
        """
    )

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
        rows = conn.execute(sql, {"after_id": int(after_id), "limit": int(limit), "event_types": event_types}).mappings().all()
        return [dict(r) for r in rows]


def _get_max_event_id() -> int:
    with engine.begin() as conn:
        row = conn.execute(text("SELECT COALESCE(max(id), 0) FROM net_events")).fetchone()
        try:
            return int(row[0] or 0)
        except Exception:
            return 0


def _load_case_by_id(conn, case_id: int) -> Optional[CaseRow]:
    row = conn.execute(
        text("SELECT id, score, max_stage, step_count, context FROM attack_chain_cases WHERE id=:id"),
        {"id": int(case_id)},
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

    with engine.begin() as conn:
        for ev in events:
            steps = detect_steps(ev, cfg)
            if not steps:
                continue

            stats["events_with_steps"] += 1
            stats["candidates"] += len(steps)

            agent_id = str(ev.get("agent_id") or "").strip()
            if not agent_id:
                continue

            for cand in steps:
                suspect_ip = cand.suspect_ip
                context_patch: Dict[str, Any] = {}

                # Track accepted SSH logins in the case context to help attach local activity.
                if cand.stage == AttackStage.initial_access and (cand.details or {}).get("action") == "accepted":
                    context_patch["last_ssh_accept_at"] = (ev.get("timestamp") or now).isoformat()
                    context_patch["last_ssh_src_ip"] = str(ev.get("src_ip") or "")
                    context_patch["last_ssh_username"] = str((cand.details or {}).get("username") or "")

                case: Optional[CaseRow] = None
                if suspect_ip:
                    case, created = get_or_create_open_case_ex(
                        conn,
                        agent_id=agent_id,
                        suspect_ip=suspect_ip,
                        now=now,
                        context_patch=context_patch or None,
                    )
                    if created:
                        stats["cases_created"] += 1
                else:
                    # Local-only steps: attach to the most recent open case for this agent.
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

                details = dict(cand.details or {})
                details.setdefault("raw_fingerprint", cand.fingerprint)

                step_id, new_score, new_max_stage = insert_step_and_update_case(
                    conn,
                    case=case,
                    stage=cand.stage,
                    label=cand.label,
                    fingerprint=fp,
                    score_delta=cand.score_delta,
                    now=now,
                    max_score=cfg.max_score,
                    event=ev,
                    details=details,
                    context_patch=context_patch or None,
                )

                touched_case_ids.add(int(case.id))
                stats["inserted"] += 1

                if bool(getattr(cfg, "debug", False)):
                    ev_id = ev.get("id")
                    ev_type = str(ev.get("event_type") or "")
                    src_ip = str(ev.get("src_ip") or "")
                    dst_ip = str(ev.get("dst_ip") or "")
                    print(
                        "[ATTACK_CHAIN] step "
                        f"case_id={case.id} step_id={step_id} stage={cand.stage.value} "
                        f"score_delta={int(cand.score_delta or 0)} new_score={new_score} max_stage={new_max_stage} "
                        f"ev_id={ev_id} ev_type={ev_type} src_ip={src_ip} dst_ip={dst_ip} "
                        f"label={cand.label!r}"
                    )

        # Periodic stale-case closure keeps the UI clean and prevents infinite open cases.
        stats["cases_closed"] = int(
            close_stale_cases(conn, now=now, idle_close_seconds=cfg.case_idle_close_seconds) or 0
        )

    stats["cases_touched"] = len(touched_case_ids)

    return last_id, stats


def main() -> None:
    cfg = load_config()

    # Keep worker startup robust even if the API service hasn't run yet.
    _ensure_bootstrap()

    # Backward-compatible config reads: older containers may have older AttackChainConfig fields.
    log_every_s = float(getattr(cfg, "log_every_seconds", 2.0))
    log_idle_every_s = float(getattr(cfg, "log_idle_every_seconds", 20.0))
    debug = bool(getattr(cfg, "debug", False))

    print(
        "[ATTACK_CHAIN] start "
        f"batch_size={cfg.batch_size} every_s={cfg.every_seconds} idle_sleep_s={cfg.idle_sleep_seconds} "
        f"dedup_s={cfg.step_dedup_seconds} attach_window_s={cfg.attach_local_window_seconds} "
        f"idle_close_s={cfg.case_idle_close_seconds} max_score={cfg.max_score} "
        f"log_every_s={log_every_s} log_idle_every_s={log_idle_every_s} debug={debug}"
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
                    print(
                        "[ATTACK_CHAIN] idle "
                        f"last_id={last_id} max_id={max_id} lag={lag} sleep_s={idle_sleep}"
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
                print(
                    "[ATTACK_CHAIN] ok "
                    f"last_id={last_id} max_id={max_id} lag={lag} "
                    f"fetched={stats.get('fetched')} events_with_steps={stats.get('events_with_steps')} "
                    f"candidates={stats.get('candidates')} inserted={stats.get('inserted')} dedup={stats.get('dedup')} "
                    f"cases_created={stats.get('cases_created')} cases_attached={stats.get('cases_attached')} "
                    f"cases_touched={stats.get('cases_touched')} cases_closed={stats.get('cases_closed')} "
                    f"took_ms={took_ms}"
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
            print(f"[ATTACK_CHAIN] db_not_ready wait_s={wait_s} error={str(e).splitlines()[0]}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            # Fail-closed: do not spin on hard failures.
            wait_s = min(backoff, 30.0)
            print(f"[ATTACK_CHAIN] error wait_s={wait_s} error={repr(e)}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
