from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from app.core.db import Base


class PortalOneTimeTokenModel(Base):
    __tablename__ = "portal_one_time_tokens"

    id = Column(String(36), primary_key=True)
    user_id = Column(Integer, index=True, nullable=False)
    created_by_user_id = Column(Integer, index=True, nullable=True)

    label = Column(String(128), nullable=True)

    token_hash = Column(String(64), unique=True, index=True, nullable=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

    used_at = Column(DateTime, nullable=True)
    used_ip = Column(String(64), nullable=True)
    used_user_agent = Column(String(256), nullable=True)

    revoked_at = Column(DateTime, nullable=True)