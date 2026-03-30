from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class CorrelationRuleModel(Base):
    """Portal-managed correlation rules.

    These rules correlate multiple alerts into higher-level incidents.
    The intent is to reduce alert fatigue and help analysts reason about
    multi-step attacks (e.g., scan -> brute force -> lateral movement).

    Notes:
    - include_patterns/exclude_patterns use shell-like wildcards (fnmatch).
    - stages is used only when strategy == "chain".
    """

    __tablename__ = "correlation_rules"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String(96), nullable=False)
    description = Column(String(255), nullable=True)

    enabled = Column(Boolean, nullable=False, default=True)
    severity = Column(String(16), nullable=False, default="high")

    # Correlation configuration
    strategy = Column(String(16), nullable=False, default="burst")  # burst | chain
    group_by = Column(String(32), nullable=False, default="src_ip")
    window_seconds = Column(Integer, nullable=False, default=600)
    min_alerts = Column(Integer, nullable=False, default=2)

    include_patterns = Column(JSONB, nullable=False, default=list)
    exclude_patterns = Column(JSONB, nullable=False, default=list)
    stages = Column(JSONB, nullable=False, default=list)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
