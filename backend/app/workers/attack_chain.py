"""Attack Chain worker.

Polls net_events and converts low-level telemetry into scored, stateful cases.

This worker is intentionally independent from the ingest path to keep ingestion
fast and predictable under load.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone, timedelta
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
from app.attack_chain.types import AttackStage, StepCandidate
from app.core.db import engine


OFFSET_NAME = "attack_chain_v1"


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
                text(
                    """
                    SELECT id, rule_type, enabled, match_mode, pattern, agent_id, username, target_user
                    FROM attack_chain_allowlist
                    WHERE rule_type = 'sudo_cmd' AND enabled = true
                    ORDER BY updated_at DESC, id DESC;
                    """
                )
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

        # SSH correlation helpers (reduce noise and improve attribution).
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS attack_chain_ssh_failures (
                    agent_id VARCHAR(64) NOT NULL,
                    src_ip VARCHAR(45) NOT NULL,
                    username TEXT NOT NULL DEFAULT '',
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    fail_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (agent_id, src_ip, username)
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS attack_chain_login_baseline (
                    agent_id VARCHAR(64) NOT NULL,
                    username TEXT NOT NULL DEFAULT '',
                    src_ip VARCHAR(45) NOT NULL,
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    seen_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (agent_id, username, src_ip)
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS attack_chain_last_access (
                    agent_id VARCHAR(64) PRIMARY KEY,
                    username TEXT NULL,
                    src_ip VARCHAR(45) NULL,
                    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_attack_chain_ssh_failures_last_seen ON attack_chain_ssh_failures (last_seen_at DESC);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_attack_chain_login_baseline_last_seen ON attack_chain_login_baseline (last_seen_at DESC);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_attack_chain_last_access_accepted_at ON attack_chain_last_access (accepted_at DESC);"))

        # Portal-managed allowlist (admin-configurable)
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS attack_chain_allowlist (
                    id SERIAL PRIMARY KEY,
                    rule_type VARCHAR(32) NOT NULL DEFAULT 'sudo_cmd',
                    enabled BOOLEAN NOT NULL DEFAULT true,
                    match_mode VARCHAR(16) NOT NULL DEFAULT 'contains',
                    pattern TEXT NOT NULL,
                    agent_id VARCHAR(64) NULL,
                    username TEXT NULL,
                    target_user TEXT NULL,
                    notes VARCHAR(256) NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_chain_allowlist_type_enabled_updated
                    ON attack_chain_allowlist (rule_type, enabled, updated_at DESC, id DESC);
                """
            )
        )

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


def _open_case_exists(conn, *, agent_id: str, suspect_ip: str) -> bool:
    row = conn.execute(
        text(
            """
            SELECT 1
            FROM attack_chain_cases
            WHERE agent_id = :agent_id
              AND suspect_ip = :suspect_ip
              AND status = 'open'
            LIMIT 1;
            """
        ),
        {"agent_id": agent_id, "suspect_ip": suspect_ip},
    ).fetchone()
    return row is not None


def _upsert_last_access(conn, *, agent_id: str, username: str, src_ip: str, accepted_at: datetime) -> None:
    conn.execute(
        text(
            """
            INSERT INTO attack_chain_last_access (agent_id, username, src_ip, accepted_at)
            VALUES (:agent_id, :username, :src_ip, :accepted_at)
            ON CONFLICT (agent_id) DO UPDATE
               SET username = EXCLUDED.username,
                   src_ip = EXCLUDED.src_ip,
                   accepted_at = EXCLUDED.accepted_at;
            """
        ),
        {"agent_id": agent_id, "username": username or None, "src_ip": src_ip or None, "accepted_at": accepted_at},
    )


def _get_recent_last_access(conn, *, agent_id: str, now: datetime, window_seconds: int) -> Optional[Dict[str, Any]]:
    if window_seconds <= 0:
        return None
    row = conn.execute(
        text(
            """
            SELECT username, src_ip, accepted_at
            FROM attack_chain_last_access
            WHERE agent_id = :agent_id
            LIMIT 1;
            """
        ),
        {"agent_id": agent_id},
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
        text(
            """
            SELECT seen_count
            FROM attack_chain_login_baseline
            WHERE agent_id = :agent_id AND username = :username AND src_ip = :src_ip
            LIMIT 1;
            """
        ),
        {"agent_id": agent_id, "username": username or "", "src_ip": src_ip},
    ).fetchone()
    first_time = row is None

    conn.execute(
        text(
            """
            INSERT INTO attack_chain_login_baseline (agent_id, username, src_ip, first_seen_at, last_seen_at, seen_count)
            VALUES (:agent_id, :username, :src_ip, :ts, :ts, 1)
            ON CONFLICT (agent_id, username, src_ip) DO UPDATE
               SET last_seen_at = EXCLUDED.last_seen_at,
                   seen_count = attack_chain_login_baseline.seen_count + 1;
            """
        ),
        {"agent_id": agent_id, "username": username or "", "src_ip": src_ip, "ts": ts},
    )

    return first_time


def _inc_ssh_failure(conn, *, agent_id: str, src_ip: str, username: str, now: datetime, window_seconds: int) -> int:
    """Increment SSH failure counter within a rolling window."""

    if window_seconds <= 0:
        window_seconds = 10 * 60

    row = conn.execute(
        text(
            """
            SELECT first_seen_at, last_seen_at, fail_count
            FROM attack_chain_ssh_failures
            WHERE agent_id = :agent_id AND src_ip = :src_ip AND username = :username
            LIMIT 1;
            """
        ),
        {"agent_id": agent_id, "src_ip": src_ip, "username": username or ""},
    ).mappings().fetchone()

    if not row:
        conn.execute(
            text(
                """
                INSERT INTO attack_chain_ssh_failures (agent_id, src_ip, username, first_seen_at, last_seen_at, fail_count)
                VALUES (:agent_id, :src_ip, :username, :now, :now, 1)
                ON CONFLICT (agent_id, src_ip, username) DO UPDATE
                   SET last_seen_at = EXCLUDED.last_seen_at,
                       fail_count = attack_chain_ssh_failures.fail_count + 1;
                """
            ),
            {"agent_id": agent_id, "src_ip": src_ip, "username": username or "", "now": now},
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
            text(
                """
                UPDATE attack_chain_ssh_failures
                   SET first_seen_at = :now,
                       last_seen_at = :now,
                       fail_count = 1
                 WHERE agent_id = :agent_id AND src_ip = :src_ip AND username = :username;
                """
            ),
            {"agent_id": agent_id, "src_ip": src_ip, "username": username or "", "now": now},
        )
        return 1

    new_count = fail_count + 1
    conn.execute(
        text(
            """
            UPDATE attack_chain_ssh_failures
               SET last_seen_at = :now,
                   fail_count = :c
             WHERE agent_id = :agent_id AND src_ip = :src_ip AND username = :username;
            """
        ),
        {"agent_id": agent_id, "src_ip": src_ip, "username": username or "", "now": now, "c": int(new_count)},
    )
    return int(new_count)


def _clear_ssh_failures(conn, *, agent_id: str, src_ip: str, username: str) -> None:
    conn.execute(
        text(
            """
            DELETE FROM attack_chain_ssh_failures
            WHERE agent_id = :agent_id AND src_ip = :src_ip AND username = :username;
            """
        ),
        {"agent_id": agent_id, "src_ip": src_ip, "username": username or ""},
    )


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

                details = dict(cand.details or {})
                details.setdefault("raw_fingerprint", cand.fingerprint)
                details.setdefault("kind", getattr(cand, "kind", "signal"))
                details.setdefault("technique_id", getattr(cand, "technique_id", None))
                details.setdefault("confidence", int(getattr(cand, "confidence", 50) or 50))
                details.setdefault("description", getattr(cand, "description", ""))

                step_id, new_score, new_max_stage = insert_step_and_update_case(
                    conn,
                    case=case,
                    stage=cand.stage,
                    label=cand.title,
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
                        f"title={cand.title!r}"
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
