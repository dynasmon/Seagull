from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class PlatformSettingModel(Base):
    __tablename__ = "platform_settings"

    key = Column(String(64), primary_key=True, index=True)
    value = Column(JSONB, nullable=False, default=dict)
    description = Column(String(255), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_by_user_id = Column(Integer, nullable=True)
    updated_by_username = Column(String(64), nullable=True)
