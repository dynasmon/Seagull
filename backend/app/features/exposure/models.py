from __future__ import annotations

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base, BigIntId


class ExposureAssetPostureModel(Base):
    __tablename__ = "exposure_asset_posture"

    id = Column(BigIntId, primary_key=True, index=True)
    asset_key = Column(String(256), unique=True, index=True, nullable=False)
    agent_id = Column(String(64), index=True, nullable=True)

    asset_type = Column(String(32), nullable=False, default="agent")
    display_name = Column(String(256), nullable=False, default="")
    hostname = Column(String(256), nullable=True)
    environment = Column(String(64), nullable=True)
    criticality = Column(String(16), nullable=False, default="unknown")

    severity = Column(String(16), nullable=False, default="unknown")
    risk_score = Column(Integer, nullable=False, default=0)
    confidence = Column(Integer, nullable=False, default=50)

    # Score components
    exposure_score = Column(Integer, nullable=False, default=0)
    vulnerability_score = Column(Integer, nullable=False, default=0)
    active_threat_score = Column(Integer, nullable=False, default=0)
    persistence_score = Column(Integer, nullable=False, default=0)
    attack_chain_score = Column(Integer, nullable=False, default=0)
    asset_criticality_score = Column(Integer, nullable=False, default=0)
    reliability_penalty = Column(Integer, nullable=False, default=0)

    status = Column(String(16), nullable=False, default="unknown")

    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    score_breakdown = Column(JSONB, nullable=False, default=dict)
    reason_codes = Column(JSONB, nullable=False, default=list)
    top_recommendations = Column(JSONB, nullable=False, default=list)
    evidence_counts = Column(JSONB, nullable=False, default=dict)
    extra_data = Column(JSONB, nullable=False, default=dict)


class ExposureNodeModel(Base):
    __tablename__ = "exposure_nodes"

    id = Column(BigIntId, primary_key=True, index=True)
    node_key = Column(String(128), unique=True, index=True, nullable=False)
    node_type = Column(String(32), index=True, nullable=False)
    asset_key = Column(String(256), index=True, nullable=True)
    agent_id = Column(String(64), index=True, nullable=True)

    label = Column(String(256), nullable=False, default="")
    severity = Column(String(16), nullable=False, default="unknown")
    risk_score = Column(Integer, nullable=False, default=0)
    confidence = Column(Integer, nullable=False, default=50)

    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    properties = Column(JSONB, nullable=False, default=dict)
    source_refs = Column(JSONB, nullable=False, default=list)


class ExposureEdgeModel(Base):
    __tablename__ = "exposure_edges"

    id = Column(BigIntId, primary_key=True, index=True)
    edge_key = Column(String(128), unique=True, index=True, nullable=False)
    source_node_key = Column(String(128), index=True, nullable=False)
    target_node_key = Column(String(128), index=True, nullable=False)
    edge_type = Column(String(64), index=True, nullable=False)
    asset_key = Column(String(256), index=True, nullable=True)
    agent_id = Column(String(64), index=True, nullable=True)

    weight = Column(Float, nullable=False, default=1.0)
    confidence = Column(Integer, nullable=False, default=50)

    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    properties = Column(JSONB, nullable=False, default=dict)
    evidence_refs = Column(JSONB, nullable=False, default=list)


class ExposureFindingModel(Base):
    __tablename__ = "exposure_findings"

    id = Column(BigIntId, primary_key=True, index=True)
    finding_key = Column(String(128), unique=True, index=True, nullable=False)
    asset_key = Column(String(256), index=True, nullable=False)
    agent_id = Column(String(64), index=True, nullable=True)
    finding_type = Column(String(32), index=True, nullable=False)
    severity = Column(String(16), index=True, nullable=False, default="unknown")

    score_delta = Column(Integer, nullable=False, default=0)
    confidence = Column(Integer, nullable=False, default=50)
    title = Column(Text, nullable=False, default="")
    summary = Column(Text, nullable=False, default="")

    status = Column(String(24), index=True, nullable=False, default="open")

    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    related_node_keys = Column(JSONB, nullable=False, default=list)
    evidence_refs = Column(JSONB, nullable=False, default=list)
    reason_codes = Column(JSONB, nullable=False, default=list)
    recommendations = Column(JSONB, nullable=False, default=list)
    extra_data = Column(JSONB, nullable=False, default=dict)


class ExposureScoreHistoryModel(Base):
    __tablename__ = "exposure_score_history"

    id = Column(BigIntId, primary_key=True, index=True)
    asset_key = Column(String(256), index=True, nullable=False)
    agent_id = Column(String(64), index=True, nullable=True)
    bucket_ts = Column(DateTime(timezone=True), index=True, nullable=False)

    risk_score = Column(Integer, nullable=False, default=0)
    severity = Column(String(16), nullable=False, default="unknown")
    confidence = Column(Integer, nullable=False, default=50)

    score_breakdown = Column(JSONB, nullable=False, default=dict)
