from sqlalchemy import JSON, Column, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base, BigIntId

SINK_CLICKHOUSE = "clickhouse"
SINK_SEARCH = "search"
SINK_WARM = "warm"


class EventOutboxModel(Base):
    __tablename__ = "event_outbox"

    id = Column(BigIntId, primary_key=True, autoincrement=True)
    sink = Column(String(32), nullable=False)
    payload = Column(JSON().with_variant(JSONB(), "postgresql"), nullable=False)
    event_count = Column(Integer, nullable=False, default=0)
    attempts = Column(Integer, nullable=False, default=0, server_default="0")
    available_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_error = Column(Text, nullable=True)

    __table_args__ = (Index("ix_event_outbox_claim", "sink", "available_at", "id"),)


class EventOutboxDeadLetterModel(Base):
    __tablename__ = "event_outbox_dead_letter"

    id = Column(BigIntId, primary_key=True, autoincrement=True)
    sink = Column(String(32), nullable=False)
    payload = Column(JSON().with_variant(JSONB(), "postgresql"), nullable=False)
    event_count = Column(Integer, nullable=False, default=0)
    attempts = Column(Integer, nullable=False, default=0)
    reason = Column(String(64), nullable=False)
    error = Column(Text, nullable=True)
    enqueued_at = Column(DateTime(timezone=True), nullable=False)
    failed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (Index("ix_event_outbox_dead_letter_sink", "sink", "failed_at"),)
