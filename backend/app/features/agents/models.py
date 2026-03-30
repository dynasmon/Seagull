from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)

    # Stable identifier set by the agent (e.g., agent-proc-1)
    agent_id = Column(String(64), unique=True, index=True, nullable=False)

    # Legacy token columns kept for schema compatibility (unused by credential auth).
    key_salt = Column(String(64), nullable=False)
    key_hash = Column(String(64), nullable=False)

    # Operational metadata
    agent_metadata = Column("metadata", JSONB, nullable=False, default=dict)

    # Human-friendly fields managed by the portal
    display_name = Column(String(128), nullable=True)
    description = Column(String(512), nullable=True)
    tags = Column(JSONB, nullable=False, default=list)

    config = Column(JSONB, nullable=False, default=dict)
    metrics = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=True)

    is_revoked = Column(Boolean, nullable=False, default=False)

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from app.core.db import Base


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

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


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
