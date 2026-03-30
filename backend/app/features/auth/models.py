from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from app.core.db import Base


class PortalUserModel(Base):
    __tablename__ = "portal_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default="admin")

    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    failed_login_count = Column(Integer, nullable=False, default=0)
    token_version = Column(Integer, nullable=False, default=1)


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
