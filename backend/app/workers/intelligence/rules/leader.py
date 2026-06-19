from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

RULES_LEADER_ADVISORY_LOCK_ID = 8714032


def try_acquire_leader_lock(connection: Connection, *, lock_id: int = RULES_LEADER_ADVISORY_LOCK_ID) -> bool:
    acquired = connection.execute(
        text("SELECT pg_try_advisory_lock(:lock_id)"),
        {"lock_id": int(lock_id)},
    ).scalar()
    return bool(acquired)


def release_leader_lock(connection: Connection, *, lock_id: int = RULES_LEADER_ADVISORY_LOCK_ID) -> bool:
    released = connection.execute(
        text("SELECT pg_advisory_unlock(:lock_id)"),
        {"lock_id": int(lock_id)},
    ).scalar()
    return bool(released)
