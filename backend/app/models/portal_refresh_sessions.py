from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from app.core.db import Base


class PortalRefreshSessionModel(Base):
    __tablename__ = "portal_refresh_sessions"

    # UUID stored as string (keeps schema simple without extra deps).
    id = Column(String(36), primary_key=True)
    family_id = Column(String(36), index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=False)

    token_hash = Column(String(64), unique=True, index=True, nullable=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    revoked_at = Column(DateTime, nullable=True)
    replaced_by_id = Column(String(36), nullable=True)

    last_ip = Column(String(64), nullable=True)
    last_user_agent = Column(String(256), nullable=True)
