from __future__ import annotations

import os
from datetime import datetime, timedelta

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "sqlite+pysqlite:///:memory:")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.audit import chain
from app.core.audit.retention import prune_audit_events
from app.core.audit.writer import audit_actor, write_audit_event
from app.core.db import Base
from app.features.admin.models import (
    AdminAuditEventModel,
    AuditChainCheckpointModel,
    AuditChainHeadModel,
)

TABLES = [
    AdminAuditEventModel.__table__,
    AuditChainHeadModel.__table__,
    AuditChainCheckpointModel.__table__,
]


@pytest.fixture()
def db():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine, tables=TABLES)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _write(db, *, action: str = "settings.update", actor_id: int = 7, **kwargs):
    row = write_audit_event(
        db,
        request=None,
        actor=audit_actor(actor_id, "admin"),
        event_type="admin_action",
        action=action,
        resource_type="settings",
        resource_id="global",
        outcome="success",
        **kwargs,
    )
    db.commit()
    return row


def _verify(db):
    return chain.verify_page(db, after_seq=chain.chain_floor(db) - 1, limit=1000)


def test_events_are_numbered_and_linked_in_order(db) -> None:
    rows = [_write(db, action=f"settings.update.{i}") for i in range(5)]

    assert [r.seq for r in rows] == [1, 2, 3, 4, 5]
    assert rows[0].prev_event_hash is None
    assert [r.prev_event_hash for r in rows[1:]] == [r.event_hash for r in rows[:-1]]


def test_the_head_tracks_the_newest_link(db) -> None:
    _write(db)
    last = _write(db)

    head = db.query(AuditChainHeadModel).filter(AuditChainHeadModel.id == chain.CHAIN_HEAD_ID).one()
    assert head.seq == last.seq
    assert head.head_hash == last.event_hash


def test_a_freshly_written_chain_verifies(db) -> None:
    for i in range(10):
        _write(db, action=f"settings.update.{i}")

    result = _verify(db)

    assert result.checked == 10
    assert result.breaks == ()


def test_the_hash_is_reproducible_from_the_stored_row(db) -> None:
    written = _write(db, before={"level": "info"}, after={"level": "debug"}, reason="tuned")
    db.expire_all()

    stored = db.query(AdminAuditEventModel).filter(AdminAuditEventModel.id == written.id).one()

    assert chain.sign_event(chain.event_payload(stored), stored.prev_event_hash) == stored.event_hash


def test_editing_a_stored_event_breaks_its_own_link(db) -> None:
    for i in range(3):
        _write(db, action=f"settings.update.{i}")

    target = db.query(AdminAuditEventModel).filter(AdminAuditEventModel.seq == 2).one()
    target.outcome = "failure"
    db.commit()

    result = _verify(db)

    assert [(b.seq, b.reason) for b in result.breaks] == [(2, chain.BREAK_EVENT_HASH_MISMATCH)]


def test_deleting_an_event_breaks_the_following_link(db) -> None:
    for i in range(3):
        _write(db, action=f"settings.update.{i}")

    db.query(AdminAuditEventModel).filter(AdminAuditEventModel.seq == 2).delete()
    db.commit()

    result = _verify(db)
    reasons = {(b.seq, b.reason) for b in result.breaks}

    assert (3, chain.BREAK_SEQ_GAP) in reasons
    assert (3, chain.BREAK_PREV_HASH_MISMATCH) in reasons


def test_repointing_a_link_is_caught_even_when_the_content_is_untouched(db) -> None:
    for i in range(3):
        _write(db, action=f"settings.update.{i}")

    target = db.query(AdminAuditEventModel).filter(AdminAuditEventModel.seq == 3).one()
    target.prev_event_hash = "0" * 64
    db.commit()

    result = _verify(db)
    reasons = {(b.seq, b.reason) for b in result.breaks}

    assert (3, chain.BREAK_PREV_HASH_MISMATCH) in reasons
    assert (3, chain.BREAK_EVENT_HASH_MISMATCH) in reasons


def test_verification_walks_the_chain_in_pages(db) -> None:
    for i in range(7):
        _write(db, action=f"settings.update.{i}")

    first = chain.verify_page(db, after_seq=0, limit=3)
    second = chain.verify_page(db, after_seq=first.last_seq, limit=3)
    third = chain.verify_page(db, after_seq=second.last_seq, limit=3)

    assert (first.checked, first.exhausted) == (3, False)
    assert (second.checked, second.exhausted) == (3, False)
    assert (third.checked, third.exhausted) == (1, True)
    assert first.breaks == second.breaks == third.breaks == ()


def _prune_oldest(db, keep_from: int = 3) -> int:
    old = datetime.utcnow() - timedelta(days=400)
    for i in range(6):
        row = _write(db, action=f"settings.update.{i}")
        if i < keep_from:
            row.created_at = old
    db.commit()
    deleted = prune_audit_events(db, datetime.utcnow() - timedelta(days=30), 100)
    db.commit()
    return deleted


def test_retention_anchors_what_it_prunes(db) -> None:
    deleted = _prune_oldest(db)

    assert deleted == 3
    checkpoint = db.query(AuditChainCheckpointModel).one()
    assert (checkpoint.from_seq, checkpoint.to_seq, checkpoint.pruned_count) == (1, 3, 3)
    assert _verify(db).breaks == ()


def test_a_pruned_range_that_loses_its_checkpoint_is_reported(db) -> None:
    _prune_oldest(db)

    db.query(AuditChainCheckpointModel).delete()
    db.commit()

    assert [b.reason for b in _verify(db).breaks] == [chain.BREAK_MISSING_PREDECESSOR]


def test_checkpoints_chain_to_each_other(db) -> None:
    first = chain.seal_pruned_range(db, from_seq=1, to_seq=3, pruned_count=3, last_event_hash="a" * 64)
    db.commit()
    second = chain.seal_pruned_range(db, from_seq=4, to_seq=9, pruned_count=6, last_event_hash="b" * 64)
    db.commit()

    assert first.prev_checkpoint_hash is None
    assert second.prev_checkpoint_hash == first.checkpoint_hash
    assert second.checkpoint_hash == chain.sign_checkpoint(
        chain.checkpoint_payload(
            created_at=second.created_at,
            from_seq=4,
            to_seq=9,
            pruned_count=6,
            last_event_hash="b" * 64,
        ),
        first.checkpoint_hash,
    )


def test_events_written_before_the_chain_are_left_below_the_floor(db) -> None:
    db.add(
        AuditChainHeadModel(id=chain.CHAIN_HEAD_ID, seq=4, head_hash=None, chain_from_seq=5)
    )
    for seq in range(1, 5):
        db.add(
            AdminAuditEventModel(
                id=f"legacy-{seq}",
                seq=seq,
                created_at=datetime.utcnow(),
                event_type="admin_action",
                action="legacy",
                outcome="success",
                resource_type="settings",
                before={},
                after={},
                changed_fields=[],
                context={},
                prev_event_hash="f" * 64,
                event_hash="e" * 64,
                schema_version=1,
            )
        )
    db.commit()

    fresh = _write(db)
    result = _verify(db)

    assert fresh.seq == 5
    assert fresh.prev_event_hash is None
    assert (result.checked, result.breaks) == (1, ())
