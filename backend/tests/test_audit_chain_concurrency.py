from __future__ import annotations

import os
import threading
import uuid

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from app.core.audit import chain
from app.core.audit.writer import audit_actor, write_audit_event
from app.features.admin.models import (
    AdminAuditEventModel,
    AuditChainCheckpointModel,
    AuditChainHeadModel,
)

MODELS = (AdminAuditEventModel, AuditChainHeadModel, AuditChainCheckpointModel)
CONTENDERS = 8

DSN = (os.environ.get("SEAGULL_TEST_DB_URL") or "").strip()

pytestmark = pytest.mark.skipif(
    not DSN.startswith("postgresql"),
    reason="set SEAGULL_TEST_DB_URL to a PostgreSQL database to run the concurrency tests",
)


@pytest.fixture()
def db_factory():
    schema = f"audit_race_{uuid.uuid4().hex[:12]}"
    admin = create_engine(DSN, poolclass=NullPool, future=True)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_engine(
        DSN,
        poolclass=NullPool,
        future=True,
        connect_args={"options": f"-csearch_path={schema}"},
    )
    for model in MODELS:
        model.__table__.create(bind=engine)

    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    db = Session()
    try:
        db.add(AuditChainHeadModel(id=chain.CHAIN_HEAD_ID, seq=0, head_hash=None, chain_from_seq=1))
        db.commit()
    finally:
        db.close()

    try:
        yield Session
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def _write_one(Session, index: int, barrier: threading.Barrier, failures: list[str]) -> None:
    db = Session()
    try:
        barrier.wait(timeout=10)
        write_audit_event(
            db,
            request=None,
            actor=audit_actor(index, f"admin-{index}"),
            event_type="admin_action",
            action="settings.update",
            resource_type="settings",
            resource_id=str(index),
            outcome="success",
            after={"index": index},
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        failures.append(repr(exc))
    finally:
        db.close()


def _race(Session, contenders: int = CONTENDERS) -> list[str]:
    barrier = threading.Barrier(contenders)
    failures: list[str] = []
    threads = [
        threading.Thread(target=_write_one, args=(Session, index, barrier, failures))
        for index in range(contenders)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    return failures


def test_concurrent_writers_produce_one_unforked_chain(db_factory) -> None:
    assert _race(db_factory) == []

    db = db_factory()
    try:
        rows = db.query(AdminAuditEventModel).order_by(AdminAuditEventModel.seq.asc()).all()
        assert [r.seq for r in rows] == list(range(1, CONTENDERS + 1))
        assert len({r.prev_event_hash for r in rows}) == CONTENDERS
        assert [r.prev_event_hash for r in rows[1:]] == [r.event_hash for r in rows[:-1]]
    finally:
        db.close()


def test_the_racing_chain_verifies(db_factory) -> None:
    _race(db_factory)

    db = db_factory()
    try:
        page = chain.verify_page(db, after_seq=0, limit=1000)
        assert page.checked == CONTENDERS
        assert page.breaks == ()
    finally:
        db.close()


def test_a_rolled_back_writer_consumes_no_link(db_factory) -> None:
    db = db_factory()
    try:
        write_audit_event(
            db,
            request=None,
            actor=audit_actor(1, "admin"),
            event_type="admin_action",
            action="settings.update",
            resource_type="settings",
            resource_id="global",
            outcome="success",
        )
        db.rollback()
    finally:
        db.close()

    assert _race(db_factory, contenders=2) == []

    db = db_factory()
    try:
        rows = db.query(AdminAuditEventModel).order_by(AdminAuditEventModel.seq.asc()).all()
        assert [r.seq for r in rows] == [1, 2]
        assert rows[0].prev_event_hash is None
        assert chain.verify_page(db, after_seq=0, limit=100).breaks == ()
    finally:
        db.close()
