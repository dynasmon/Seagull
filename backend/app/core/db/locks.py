from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import text
from sqlalchemy.engine import Connection

from .engine import engine


@contextmanager
def advisory_lock(lock_id: int, poll_interval: float = 0.5) -> Iterator[Connection]:
    conn = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
    try:
        while not conn.execute(
            text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}
        ).scalar():
            time.sleep(poll_interval)
        try:
            yield conn
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})
    finally:
        conn.close()
