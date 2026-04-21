from sqlalchemy import Boolean, Column, DateTime, Integer, SmallInteger, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class VulnScanModel(Base):
    __tablename__ = "vuln_scans"

    id = Column(Integer, primary_key=True)
    scan_uuid = Column(String(36), unique=True, index=True, nullable=False)

    # Which agent produced the scan (can be a dedicated scanner agent).
    reporter_agent_id = Column(String(64), index=True, nullable=True)

    # Optional human label for the scan target (e.g., "192.168.0.0/24" or "agent:<id>").
    target = Column(Text, nullable=True)

    tool = Column(String(64), nullable=False, default="unknown")
    tool_version = Column(String(64), nullable=True)

    status = Column(String(24), nullable=False, default="queued")
    lifecycle_state = Column(String(24), nullable=False, default="queued")
    current_phase = Column(String(32), nullable=False, default="queued")

    queued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    last_progress_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    trigger_source = Column(String(24), nullable=False, default="scheduled")
    error_summary = Column(String(512), nullable=True)

    # JSON payloads for extensibility: scopes, scanner config, stats.
    scope = Column(JSONB, nullable=False, default=dict)
    config = Column(JSONB, nullable=False, default=dict)
    stats = Column(JSONB, nullable=False, default=dict)
    phase_timestamps = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    @property
    def duration_ms(self) -> int | None:
        if self.started_at is None:
            return None
        end = self.finished_at or self.last_progress_at
        if end is None:
            return None
        return max(0, int((end - self.started_at).total_seconds() * 1000))


class VulnFindingModel(Base):
    __tablename__ = "vuln_findings"

    __table_args__ = (
        UniqueConstraint("asset_key", "fingerprint", name="uq_vuln_findings_asset_fp"),
    )

    id = Column(Integer, primary_key=True)

    # Scan association is optional because findings can be streamed.
    scan_id = Column(Integer, nullable=True)

    # Asset identity:
    # - asset_key is the primary identity for deduplication and pagination.
    #   Examples: "agent:<agent_id>", "ip:10.0.0.5", "url:https://example.com".
    asset_key = Column(String(256), index=True, nullable=False)

    # If the asset maps to an enrolled Seagull agent, store its id.
    asset_agent_id = Column(String(64), index=True, nullable=True)

    # Which agent produced the finding (can differ from asset_agent_id).
    reporter_agent_id = Column(String(64), index=True, nullable=True)

    target = Column(Text, nullable=True)
    asset = Column(JSONB, nullable=False, default=dict)

    source = Column(String(32), nullable=False, default="unknown")
    external_id = Column(String(128), nullable=True)

    fingerprint = Column(String(64), nullable=False)

    severity = Column(String(16), nullable=False, default="unknown")
    severity_rank = Column(SmallInteger, nullable=False, default=0)
    confidence = Column(SmallInteger, nullable=False, default=50)

    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    cve = Column(String(32), nullable=True)
    cwe = Column(String(32), nullable=True)
    cvss = Column(String(16), nullable=True)

    location = Column(Text, nullable=True)
    tags = Column(JSONB, nullable=False, default=list)

    evidence = Column(JSONB, nullable=False, default=dict)

    status = Column(String(24), nullable=False, default="open")
    is_suppressed = Column(Boolean, nullable=False, default=False)
    observation_state = Column(String(32), nullable=False, default="observed")
    operator_disposition = Column(String(32), nullable=False, default="open")

    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    occurrences = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
