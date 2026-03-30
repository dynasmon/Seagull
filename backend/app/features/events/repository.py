from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session


def run(db: Session, stmt: Any):
    return db.execute(stmt)
