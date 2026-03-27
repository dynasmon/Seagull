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
