import enum
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AgentCertificateStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), unique=True, index=True, nullable=False)

    agent_metadata = Column("metadata", JSONB, nullable=False, default=dict)

    display_name = Column(String(128), nullable=True)
    description = Column(String(512), nullable=True)
    tags = Column(JSONB, nullable=False, default=list)

    config = Column(JSONB, nullable=False, default=dict)
    metrics = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=True)

    observed_address = Column(String(45), nullable=True)
    observed_address_at = Column(DateTime, nullable=True)

    is_revoked = Column(Boolean, nullable=False, default=False)


class AgentCredentialModel(Base):
    __tablename__ = "agent_credentials"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True, nullable=False)
    credential_salt = Column(String(64), nullable=False)
    credential_hash = Column(String(64), unique=True, index=True, nullable=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    max_uses = Column(Integer, nullable=False, default=1)
    used_uses = Column(Integer, nullable=False, default=0)
    last_used_at = Column(DateTime, nullable=True)

    rotated_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(256), nullable=True)

    issued_from_bootstrap_token_id = Column(Integer, nullable=True)
    replaces_credential_id = Column(Integer, nullable=True)


class AgentBootstrapTokenModel(Base):
    __tablename__ = "agent_bootstrap_tokens"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(String(64), index=True, nullable=False)
    token_salt = Column(String(64), nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    token_type = Column(String(16), nullable=False, default="enrollment")

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


class AgentCertificateModel(Base):
    __tablename__ = "agent_certificates"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), index=True, nullable=False)
    serial_hex = Column(String(64), index=True, nullable=False)
    fingerprint_sha256 = Column(String(64), unique=True, index=True, nullable=False)
    subject = Column(String(256), nullable=False)
    public_key_sha256 = Column(String(64), index=True, nullable=False)

    issued_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(256), nullable=True)

    status = Column(String(16), nullable=False, default=AgentCertificateStatus.active.value)
