from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Connection

from app.core.db import engine
from app.shared.indexing.models import SearchIndexOffsetModel


def _ensure_offset_row(conn: Connection, *, name: str, initial_last_id: int) -> None:
    conn.execute(
        insert(SearchIndexOffsetModel)
        .values(name=name, last_id=int(initial_last_id))
        .on_conflict_do_nothing(index_elements=[SearchIndexOffsetModel.name])
    )


def ensure_offset(name: str, *, initial_last_id: int = 0, conn: Connection | None = None) -> None:
    if conn is not None:
        _ensure_offset_row(conn, name=name, initial_last_id=initial_last_id)
        return
    with engine.begin() as local_conn:
        _ensure_offset_row(local_conn, name=name, initial_last_id=initial_last_id)


def ensure_offsets(names: Iterable[str], *, initial_last_id: int = 0, conn: Connection | None = None) -> None:
    if conn is not None:
        for name in names:
            _ensure_offset_row(conn, name=str(name), initial_last_id=initial_last_id)
        return
    with engine.begin() as local_conn:
        for name in names:
            _ensure_offset_row(local_conn, name=str(name), initial_last_id=initial_last_id)


def get_offset(name: str, *, default: int = 0, conn: Connection | None = None) -> int:
    if conn is not None:
        row = conn.execute(
            select(SearchIndexOffsetModel.last_id).where(SearchIndexOffsetModel.name == name).limit(1)
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else int(default)
    with engine.begin() as local_conn:
        row = local_conn.execute(
            select(SearchIndexOffsetModel.last_id).where(SearchIndexOffsetModel.name == name).limit(1)
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else int(default)


def set_offset(name: str, last_id: int, *, conn: Connection | None = None) -> None:
    stmt = (
        insert(SearchIndexOffsetModel)
        .values(name=name, last_id=int(last_id))
        .on_conflict_do_update(
            index_elements=[SearchIndexOffsetModel.name],
            set_={"last_id": int(last_id), "updated_at": func.now()},
        )
    )
    if conn is not None:
        conn.execute(stmt)
        return
    with engine.begin() as local_conn:
        local_conn.execute(stmt)
