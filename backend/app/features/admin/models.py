from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, BigInteger, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base

_JSON = JSON().with_variant(JSONB(), "postgresql")


class AdminAuditEventModel(Base):
    __tablename__ = "admin_audit_events"

    id = Column(String(36), primary_key=True)
    seq = Column(BigInteger, nullable=True, unique=True, index=True)
    operation_id = Column(String(36), nullable=True, index=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    event_type = Column(String(32), nullable=False, index=True, default="admin_action")
    action = Column(String(96), nullable=False, index=True)
    outcome = Column(String(16), nullable=False, index=True, default="success")  # success | failure | denied

    actor_user_id = Column(Integer, nullable=True, index=True)
    actor_username = Column(String(64), nullable=True, index=True)

    resource_type = Column(String(48), nullable=False, index=True)
    resource_id = Column(String(128), nullable=True, index=True)

    request_id = Column(String(64), nullable=True, index=True)
    trace_id = Column(String(128), nullable=True, index=True)
    ip = Column(String(64), nullable=True)
    user_agent = Column(String(256), nullable=True)
    method = Column(String(16), nullable=True)
    path = Column(String(255), nullable=True)

    reason = Column(String(255), nullable=True)
    error = Column(String(255), nullable=True)

    before = Column(_JSON, nullable=False, default=dict)
    after = Column(_JSON, nullable=False, default=dict)
    changed_fields = Column(_JSON, nullable=False, default=list)
    context = Column(_JSON, nullable=False, default=dict)

    prev_event_hash = Column(String(64), nullable=True)
    event_hash = Column(String(64), nullable=True, index=True)
    schema_version = Column(Integer, nullable=False, default=1)


class AuditChainHeadModel(Base):
    __tablename__ = "audit_chain_head"

    id = Column(Integer, primary_key=True, autoincrement=False)
    seq = Column(BigInteger, nullable=False, default=0)
    head_hash = Column(String(64), nullable=True)
    chain_from_seq = Column(BigInteger, nullable=False, default=1)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class AuditChainCheckpointModel(Base):
    __tablename__ = "audit_chain_checkpoints"

    id = Column(String(36), primary_key=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    from_seq = Column(BigInteger, nullable=False)
    to_seq = Column(BigInteger, nullable=False, index=True)
    pruned_count = Column(Integer, nullable=False, default=0)
    last_event_hash = Column(String(64), nullable=True)
    prev_checkpoint_hash = Column(String(64), nullable=True)
    checkpoint_hash = Column(String(64), nullable=False)
