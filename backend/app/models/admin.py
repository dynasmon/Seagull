from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.core.db import Base


class AdminUserModel(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    password_changed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    logins = relationship("AdminLoginEventModel", back_populates="user", cascade="all,delete-orphan")
    refresh_tokens = relationship("AdminRefreshTokenModel", back_populates="user", cascade="all,delete-orphan")


class AdminLoginEventModel(Base):
    __tablename__ = "admin_login_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("admin_users.id", ondelete="CASCADE"), index=True, nullable=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    ip = Column(String(64), nullable=True)
    user_agent = Column(String(256), nullable=True)
    success = Column(Boolean, nullable=False, default=False)

    user = relationship("AdminUserModel", back_populates="logins")


class AdminRefreshTokenModel(Base):
    __tablename__ = "admin_refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("admin_users.id", ondelete="CASCADE"), index=True, nullable=False)

    jti_hash = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    user = relationship("AdminUserModel", back_populates="refresh_tokens")
