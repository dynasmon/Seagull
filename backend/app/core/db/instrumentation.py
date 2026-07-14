from __future__ import annotations

import re
import time
from functools import lru_cache
from typing import Any, Sequence

from sqlalchemy import event
from sqlalchemy.engine import Engine

from app.core.observability import observe_hist, set_gauge

_TABLE_PATTERN = re.compile(r"\b(?:from|into|update|join)\s+(?:only\s+)?\"?([a-zA-Z_][A-Za-z0-9_$]*)", re.IGNORECASE)


@lru_cache(maxsize=2048)
def statement_table(statement: str) -> str:
    match = _TABLE_PATTERN.search(statement)
    if match is None:
        return "none"
    return match.group(1).lower()[:63]


def _table_label(statement: str) -> str:
    return statement_table(statement[:2048])


def instrument_query_timing(target: Engine, role: str) -> None:
    @event.listens_for(target, "before_cursor_execute")
    def before_cursor_execute(
        conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool
    ) -> None:
        conn.info.setdefault("seagull_query_start", []).append(time.perf_counter())

    @event.listens_for(target, "after_cursor_execute")
    def after_cursor_execute(
        conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: bool
    ) -> None:
        stack = conn.info.get("seagull_query_start")
        if not stack:
            return
        elapsed = time.perf_counter() - stack.pop()
        observe_hist("postgres_query_seconds", elapsed, engine=role, table=_table_label(statement))


def instrument_pool_gauge(targets: Sequence[Engine], role: str, capacity: int) -> None:
    engines = tuple(targets)
    denominator = float(max(1, int(capacity)))

    def update(*args: Any) -> None:
        checked_out = 0
        for target in engines:
            checkedout = getattr(target.pool, "checkedout", None)
            if callable(checkedout):
                checked_out += int(checkedout())
        set_gauge("postgres_pool_saturation", checked_out / denominator, engine=role)

    for target in engines:
        event.listen(target, "checkout", update)
        event.listen(target, "checkin", update)
