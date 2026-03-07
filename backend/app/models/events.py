from sqlalchemy import Boolean, Column, DateTime, Integer, BigInteger, String, func, SmallInteger
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class NetEventModel(Base):
    __tablename__ = "net_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), index=True, nullable=False)
    event_type = Column(String(32), index=True, nullable=False)
    schema_version = Column(SmallInteger, nullable=False, default=1)
    timestamp = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())

    src_ip = Column(String(45), index=True, nullable=True)
    dst_ip = Column(String(45), index=True, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    proto = Column(String(16), nullable=True)
    bytes = Column(Integer, nullable=True)

    # JSONB enables expression/GIN indexes and faster key extraction in Postgres.
    extra = Column(JSONB, nullable=False, default=dict)


class NetEventRollup1sModel(Base):
    __tablename__ = "net_event_rollups_1s"

    bucket_ts = Column(DateTime(timezone=True), primary_key=True, nullable=False)
    agent_id = Column(String(64), primary_key=True, nullable=False)
    event_type = Column(String(32), primary_key=True, nullable=False)

    dst_ip = Column(String(45), primary_key=True, nullable=True)
    dst_port = Column(Integer, primary_key=True, nullable=True)
    proto = Column(String(16), primary_key=True, nullable=True)

    count = Column(BigInteger, nullable=False, default=0)
    bytes_sum = Column(BigInteger, nullable=False, default=0)


class EventRollup1mModel(Base):
    __tablename__ = "event_rollups_1m"

    bucket_ts = Column(DateTime(timezone=True), primary_key=True, nullable=False)
    agent_id = Column(String(64), primary_key=True, nullable=False)
    event_type = Column(String(32), primary_key=True, nullable=False)
    count = Column(BigInteger, nullable=False, default=0)


class SshFailRollup1mModel(Base):
    __tablename__ = "ssh_fail_rollups_1m"

    bucket_ts = Column(DateTime(timezone=True), primary_key=True, nullable=False)
    agent_id = Column(String(64), primary_key=True, nullable=False)
    action = Column(String(64), primary_key=True, nullable=False)
    count = Column(BigInteger, nullable=False, default=0)


class IngestStats1sModel(Base):
    __tablename__ = "ingest_stats_1s"

    bucket_ts = Column(DateTime(timezone=True), primary_key=True, nullable=False)
    received = Column(BigInteger, nullable=False, default=0)
    hot_stored = Column(BigInteger, nullable=False, default=0)
    warm_indexed = Column(BigInteger, nullable=False, default=0)
    dropped = Column(BigInteger, nullable=False, default=0)
    rejected = Column(BigInteger, nullable=False, default=0)
    rollup_only = Column(BigInteger, nullable=False, default=0)
    backlog_messages = Column(BigInteger, nullable=False, default=0)
    backlog_events = Column(BigInteger, nullable=False, default=0)
    storm_active = Column(Boolean, nullable=False, default=False)
    sample_hot_percent = Column(SmallInteger, nullable=False, default=100)
    sample_warm_percent = Column(SmallInteger, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
