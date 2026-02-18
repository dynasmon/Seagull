from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base


class AttackChainCaseModel(Base):
    """Stateful, scored attack-chain case.

    A case is a timeline of evidence (steps) that suggests an attacker progressing
    through stages (initial access -> execution -> persistence ...).

    Cases are intentionally modeled as durable state so the UI can show a clean,
    operator-friendly narrative instead of raw event noise.
    """

    __tablename__ = "attack_chain_cases"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(String(64), index=True, nullable=False)

    # Primary suspect (usually a remote source IP). May be NULL for purely local chains.
    suspect_ip = Column(String(45), index=True, nullable=True)

    status = Column(String(16), index=True, nullable=False, default="open")  # open | closed

    score = Column(Integer, nullable=False, default=0)
    max_stage = Column(String(32), nullable=False, default="initial_access")

    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    closed_at = Column(DateTime(timezone=True), nullable=True)

    # Fast UI counters / lightweight, queryable state.
    step_count = Column(Integer, nullable=False, default=0)

    # Arbitrary state (counters, last_seen markers, derived metadata)
    context = Column(JSONB, nullable=False, default=dict)


class AttackChainStepModel(Base):
    __tablename__ = "attack_chain_steps"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("attack_chain_cases.id", ondelete="CASCADE"), index=True, nullable=False)

    stage = Column(String(32), index=True, nullable=False)
    label = Column(String(96), nullable=False)
    score_delta = Column(Integer, nullable=False, default=0)

    # Used for deduplication (noise control) across short windows.
    fingerprint = Column(String(192), index=True, nullable=False)

    # References back to the original telemetry evidence (optional but preferred).
    event_id = Column(Integer, ForeignKey("net_events.id", ondelete="SET NULL"), index=True, nullable=True)
    event_type = Column(String(32), nullable=True)

    timestamp = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    proto = Column(String(16), nullable=True)

    # Step metadata intended for UI (aggregates, extracted fields, etc.)
    details = Column(JSONB, nullable=False, default=dict)
