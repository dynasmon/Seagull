from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from app.core.db import Base


class PortalLoginEventModel(Base):
    __tablename__ = "portal_login_events"

    id = Column(String(36), primary_key=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(64), nullable=True, index=True)

    method = Column(String(16), nullable=False)  # e.g. "password", "otp"
    succeeded = Column(Boolean, nullable=False, default=True)

    ip = Column(String(64), nullable=True)
    user_agent = Column(String(256), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
