"""Rollup worker (1-minute buckets) to reduce dashboard load on Postgres."""

from __future__ import annotations

import os
import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.core.db import engine


OFFSET_EVENTS = "rollup_events_1m"
OFFSET_SSH_FAIL = "rollup_ssh_fail_1m"

SSH_FAIL_ACTIONS: tuple[str, ...] = (
    "invalid_password",
    "invalid_user",
    "max_auth_attempts",
)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _ensure_bootstrap() -> None:
    """Ensure the minimal tables this worker depends on exist.

    The backend also runs a bootstrap, but in Docker Compose workers may start first.
    This keeps the system self-healing and reduces noisy startup failures.
    """
    with engine.begin() as conn:
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
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS event_rollups_1m (
                    bucket_ts TIMESTAMPTZ NOT NULL,
                    agent_id VARCHAR(64) NOT NULL,
                    event_type VARCHAR(32) NOT NULL,
                    count BIGINT NOT NULL DEFAULT 0,
                    PRIMARY KEY (bucket_ts, agent_id, event_type)
                );
                """
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_event_rollups_1m_bucket ON event_rollups_1m (bucket_ts DESC);"))

        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS ssh_fail_rollups_1m (
                    bucket_ts TIMESTAMPTZ NOT NULL,
                    agent_id VARCHAR(64) NOT NULL,
                    action VARCHAR(64) NOT NULL,
                    count BIGINT NOT NULL DEFAULT 0,
                    PRIMARY KEY (bucket_ts, agent_id, action)
                );
                """
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_ssh_fail_rollups_1m_bucket ON ssh_fail_rollups_1m (bucket_ts DESC);"))

        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets (name, last_id)
                VALUES (:n, 0)
                ON CONFLICT (name) DO NOTHING;
                """
            ),
            {"n": OFFSET_EVENTS},
        )
        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets (name, last_id)
                VALUES (:n, 0)
                ON CONFLICT (name) DO NOTHING;
                """
            ),
            {"n": OFFSET_SSH_FAIL},
        )


def _get_last_id(name: str) -> int:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT last_id FROM search_index_offsets WHERE name=:name"),
            {"name": name},
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0


def _set_last_id(name: str, last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets(name, last_id)
                VALUES (:name, :last_id)
                ON CONFLICT (name) DO UPDATE
                  SET last_id = EXCLUDED.last_id,
                      updated_at = now();
                """
            ),
            {"name": name, "last_id": int(last_id)},
        )


def _pick_batch_max_id(last_id: int, max_rows: int) -> int | None:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT MAX(id) FROM (
                    SELECT id
                    FROM net_events
                    WHERE id > :last_id
                    ORDER BY id
                    LIMIT :max_rows
                ) t;
                """
            ),
            {"last_id": int(last_id), "max_rows": int(max_rows)},
        ).fetchone()
        v = row[0] if row else None
        return int(v) if v is not None else None


def _rollup_events(last_id: int, max_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                WITH batch AS (
                    SELECT
                        date_trunc('minute', "timestamp") AS bucket_ts,
                        agent_id,
                        event_type
                    FROM net_events
                    WHERE id > :last_id AND id <= :max_id
                ),
                agg AS (
                    SELECT bucket_ts, agent_id, event_type, COUNT(*)::bigint AS c
                    FROM batch
                    GROUP BY 1, 2, 3
                )
                INSERT INTO event_rollups_1m(bucket_ts, agent_id, event_type, count)
                SELECT bucket_ts, agent_id, event_type, c
                FROM agg
                ON CONFLICT (bucket_ts, agent_id, event_type)
                DO UPDATE SET count = event_rollups_1m.count + EXCLUDED.count;
                """
            ),
            {"last_id": int(last_id), "max_id": int(max_id)},
        )


def _rollup_ssh_fail(last_id: int, max_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                WITH batch AS (
                    SELECT
                        date_trunc('minute', "timestamp") AS bucket_ts,
                        agent_id,
                        (extra->>'action') AS action
                    FROM net_events
                    WHERE id > :last_id AND id <= :max_id
                      AND event_type = 'ssh_auth'
                      AND (extra->>'action') = ANY(:actions)
                ),
                agg AS (
                    SELECT bucket_ts, agent_id, action, COUNT(*)::bigint AS c
                    FROM batch
                    GROUP BY 1, 2, 3
                )
                INSERT INTO ssh_fail_rollups_1m(bucket_ts, agent_id, action, count)
                SELECT bucket_ts, agent_id, action, c
                FROM agg
                ON CONFLICT (bucket_ts, agent_id, action)
                DO UPDATE SET count = ssh_fail_rollups_1m.count + EXCLUDED.count;
                """
            ),
            {"last_id": int(last_id), "max_id": int(max_id), "actions": list(SSH_FAIL_ACTIONS)},
        )


def main() -> None:
    every_s = _env_float("NETWATCH_ROLLUP_EVERY_SECONDS", 1.0)
    idle_sleep_s = _env_float("NETWATCH_ROLLUP_IDLE_SLEEP_SECONDS", 2.0)
    max_rows = _env_int("NETWATCH_ROLLUP_MAX_ROWS", 5000)

    backoff = 1.0

    while True:
        try:
            _ensure_bootstrap()

            last_events_id = _get_last_id(OFFSET_EVENTS)
            last_ssh_id = _get_last_id(OFFSET_SSH_FAIL)

            # Keep progress monotonic across both rollups.
            last_id = min(last_events_id, last_ssh_id)
            max_id = _pick_batch_max_id(last_id, max_rows)

            if max_id is None or max_id <= last_id:
                time.sleep(idle_sleep_s)
                backoff = 1.0
                continue

            t0 = time.time()
            _rollup_events(last_events_id, max_id)
            _set_last_id(OFFSET_EVENTS, max_id)

            _rollup_ssh_fail(last_ssh_id, max_id)
            _set_last_id(OFFSET_SSH_FAIL, max_id)

            took_ms = int((time.time() - t0) * 1000)
            print(f"[ROLLUP] ok last_id={last_id} max_id={max_id} rows~{max_rows} took_ms={took_ms}")

            backoff = 1.0
            time.sleep(max(every_s, 0.1))
        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            print(f"[ROLLUP] db_not_ready wait_s={wait_s} error={str(e).splitlines()[0]}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 15.0)
            print(f"[ROLLUP] error wait_s={wait_s} error={repr(e)}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)


if __name__ == "__main__":
    main()
