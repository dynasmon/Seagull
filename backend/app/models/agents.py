from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)

    # Stable identifier set by the agent (e.g., agent-proc-1)
    agent_id = Column(String(64), unique=True, index=True, nullable=False)

    # Auth token components (never store the raw secret)
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
