"""Rollup worker (1-minute buckets) to reduce dashboard load on Postgres."""

from __future__ import annotations

import os
import time

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import OperationalError

from app.core.db import Base, engine
from app.core.schema_bootstrap import bootstrap_schema
from app.models.events import EventRollup1mModel, NetEventModel, SshFailRollup1mModel
from app.models.search_index_offsets import SearchIndexOffsetModel


OFFSET_EVENTS = "rollup_events_1m"
OFFSET_SSH_FAIL = "rollup_ssh_fail_1m"

SSH_FAIL_ACTIONS: tuple[str, ...] = (
    "failed_password",
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
    Base.metadata.create_all(bind=engine)
    bootstrap_schema(engine)
    with engine.begin() as conn:
        for name in [OFFSET_EVENTS, OFFSET_SSH_FAIL]:
            conn.execute(
                insert(SearchIndexOffsetModel)
                .values(name=name, last_id=0)
                .on_conflict_do_nothing(index_elements=[SearchIndexOffsetModel.name])
            )


def _get_last_id(name: str) -> int:
    with engine.begin() as conn:
        row = conn.execute(
            select(SearchIndexOffsetModel.last_id).where(SearchIndexOffsetModel.name == name).limit(1)
        ).first()
        return int(row[0]) if row and row[0] is not None else 0


def _set_last_id(name: str, last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            insert(SearchIndexOffsetModel)
            .values(name=name, last_id=int(last_id))
            .on_conflict_do_update(
                index_elements=[SearchIndexOffsetModel.name],
                set_={"last_id": int(last_id), "updated_at": func.now()},
            )
        )


def _pick_batch_max_id(last_id: int, max_rows: int) -> int | None:
    with engine.begin() as conn:
        subq = (
            select(NetEventModel.id)
            .where(NetEventModel.id > int(last_id))
            .order_by(NetEventModel.id.asc())
            .limit(int(max_rows))
            .subquery()
        )
        row = conn.execute(select(func.max(subq.c.id))).fetchone()
        v = row[0] if row else None
        return int(v) if v is not None else None


def _rollup_events(last_id: int, max_id: int) -> None:
    with engine.begin() as conn:
        rows = conn.execute(
            select(
                func.date_trunc("minute", NetEventModel.timestamp).label("bucket_ts"),
                NetEventModel.agent_id.label("agent_id"),
                NetEventModel.event_type.label("event_type"),
                func.count().label("count"),
            )
            .where(NetEventModel.id > int(last_id), NetEventModel.id <= int(max_id))
            .group_by("bucket_ts", NetEventModel.agent_id, NetEventModel.event_type)
        ).mappings().all()
        if not rows:
            return

        ins = insert(EventRollup1mModel).values(
            [
                {
                    "bucket_ts": r["bucket_ts"],
                    "agent_id": r["agent_id"],
                    "event_type": r["event_type"],
                    "count": int(r["count"] or 0),
                }
                for r in rows
            ]
        )
        conn.execute(
            ins.on_conflict_do_update(
                index_elements=[EventRollup1mModel.bucket_ts, EventRollup1mModel.agent_id, EventRollup1mModel.event_type],
                set_={"count": EventRollup1mModel.count + ins.excluded.count},
            )
        )


def _rollup_ssh_fail(last_id: int, max_id: int) -> None:
    with engine.begin() as conn:
        action_expr = NetEventModel.extra["action"].astext
        rows = conn.execute(
            select(
                func.date_trunc("minute", NetEventModel.timestamp).label("bucket_ts"),
                NetEventModel.agent_id.label("agent_id"),
                action_expr.label("action"),
                func.count().label("count"),
            )
            .where(
                NetEventModel.id > int(last_id),
                NetEventModel.id <= int(max_id),
                NetEventModel.event_type == "ssh_auth",
                action_expr.in_(list(SSH_FAIL_ACTIONS)),
            )
            .group_by("bucket_ts", NetEventModel.agent_id, action_expr)
        ).mappings().all()
        if not rows:
            return

        ins = insert(SshFailRollup1mModel).values(
            [
                {
                    "bucket_ts": r["bucket_ts"],
                    "agent_id": r["agent_id"],
                    "action": r["action"],
                    "count": int(r["count"] or 0),
                }
                for r in rows
            ]
        )
        conn.execute(
            ins.on_conflict_do_update(
                index_elements=[SshFailRollup1mModel.bucket_ts, SshFailRollup1mModel.agent_id, SshFailRollup1mModel.action],
                set_={"count": SshFailRollup1mModel.count + ins.excluded.count},
            )
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
