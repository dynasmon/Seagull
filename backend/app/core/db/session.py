from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from fastapi.params import Depends as DependsParam
from sqlalchemy.orm import Session

from .engine import SessionLocal


def resolve_session(db: Session | object) -> tuple[Session, bool]:

    if isinstance(db, Session):
        return db, False
    if isinstance(db, DependsParam) or db is None:
        real = SessionLocal()
        return real, True
    return db, False  # type: ignore[return-value]


@contextmanager
def managed_session(db: Session | object) -> Iterator[Session]:
    session, owns = resolve_session(db)
    try:
        yield session
    finally:
        if owns:
            session.close()
