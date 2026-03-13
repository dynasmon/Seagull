from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AgentIdentityModel(Base):
    __tablename__ = "agent_identities"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True, nullable=False)
    fingerprint_sha256 = Column(String(128), unique=True, index=True, nullable=False)
    serial_number = Column(String(128), nullable=False)
    subject_dn = Column(String(512), nullable=False)
    issuer_dn = Column(String(512), nullable=True)

    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=True)

    is_revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(256), nullable=True)

    identity_metadata = Column("metadata", JSONB, nullable=False, default=dict)


class AgentBootstrapTokenModel(Base):
    __tablename__ = "agent_bootstrap_tokens"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(String(64), index=True, nullable=False)
    token_salt = Column(String(64), nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    max_uses = Column(Integer, nullable=False, default=1)
    used_uses = Column(Integer, nullable=False, default=0)
    last_used_at = Column(DateTime, nullable=True)

    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(256), nullable=True)

    created_by_user_id = Column(Integer, nullable=True)
    description = Column(String(256), nullable=True)
    token_metadata = Column("metadata", JSONB, nullable=False, default=dict)
