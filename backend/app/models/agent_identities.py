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
