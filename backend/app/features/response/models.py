from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class ResponseActionModel(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)

    action_type = Column(String(32), nullable=False)
    agent_id = Column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True, nullable=False)
    status = Column(String(16), index=True, nullable=False, default="pending")

    payload = Column(JSONB, nullable=False, default=dict)
    requested_by = Column(String(64), nullable=False)
    requested_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)


class ResponseActionResultModel(Base):
    __tablename__ = "response_action_results"

    id = Column(Integer, primary_key=True, index=True)

    response_action_id = Column(Integer, ForeignKey("response_actions.id", ondelete="CASCADE"), index=True, nullable=False)
    agent_id = Column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True, nullable=False)
    status = Column(String(16), index=True, nullable=False, default="queued")

    result_payload = Column(JSONB, nullable=False, default=dict)
    error = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), index=True, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
