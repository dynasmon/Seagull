from __future__ import annotations

from sqlalchemy import Column, DateTime, Float, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.db import Base, BigIntId


class TopologyNodeModel(Base):
    __tablename__ = "network_topology_nodes"

    id = Column(BigIntId, primary_key=True, index=True)
    node_key = Column(String(256), unique=True, index=True, nullable=False)
    node_type = Column(String(32), index=True, nullable=False)
    agent_id = Column(String(64), index=True, nullable=True)
    label = Column(String(256), nullable=False, default="")
    ip = Column(String(64), index=True, nullable=True)
    cidr = Column(String(64), index=True, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    severity = Column(String(16), index=True, nullable=False, default="unknown")
    risk_score = Column(Integer, nullable=False, default=0)
    confidence = Column(Integer, nullable=False, default=50)
    is_stale = Column(Integer, nullable=False, default=0)
    event_count = Column(Integer, nullable=False, default=0)
    alert_count = Column(Integer, nullable=False, default=0)
    observation_count = Column(Integer, nullable=False, default=0)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    extra_data = Column(JSONB, nullable=False, default=dict)


class TopologyEdgeModel(Base):
    __tablename__ = "network_topology_edges"

    id = Column(BigIntId, primary_key=True, index=True)
    edge_key = Column(String(256), unique=True, index=True, nullable=False)
    source_node_key = Column(String(256), index=True, nullable=False)
    target_node_key = Column(String(256), index=True, nullable=False)
    edge_type = Column(String(64), index=True, nullable=False)
    agent_id = Column(String(64), index=True, nullable=True)
    weight = Column(Float, nullable=False, default=1.0)
    confidence = Column(Integer, nullable=False, default=50)
    severity = Column(String(16), index=True, nullable=False, default="unknown")
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    event_count = Column(Integer, nullable=False, default=0)
    alert_count = Column(Integer, nullable=False, default=0)
    first_seen_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), index=True, nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    extra_data = Column(JSONB, nullable=False, default=dict)


class TopologyObservationModel(Base):
    __tablename__ = "network_topology_observations"

    id = Column(BigIntId, primary_key=True, index=True)
    node_key = Column(String(256), index=True, nullable=False)
    edge_key = Column(String(256), index=True, nullable=True)
    agent_id = Column(String(64), index=True, nullable=True)
    source_type = Column(String(32), index=True, nullable=False)
    source_id = Column(String(128), nullable=True)
    observed_at = Column(DateTime(timezone=True), index=True, nullable=False)
    summary = Column(String(512), nullable=False, default="")
    raw_context = Column(JSONB, nullable=False, default=dict)


class TopologySnapshotModel(Base):
    __tablename__ = "network_topology_snapshots"

    id = Column(BigIntId, primary_key=True, index=True)
    snapshot_key = Column(String(128), unique=True, index=True, nullable=False)
    node_count = Column(Integer, nullable=False, default=0)
    edge_count = Column(Integer, nullable=False, default=0)
    agent_count = Column(Integer, nullable=False, default=0)
    subnet_count = Column(Integer, nullable=False, default=0)
    external_ip_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    coverage = Column(JSONB, nullable=False, default=dict)
    metrics = Column(JSONB, nullable=False, default=dict)
