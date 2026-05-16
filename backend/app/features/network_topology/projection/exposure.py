from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.features.exposure.models import ExposureAssetPostureModel
from app.features.network_topology import repository
from app.features.network_topology.projection.helpers import _edge_key, _node_key, _to_utc
from app.features.network_topology.schemas import TopologyCoverageOut

_MAX_EXPOSURE_ROWS = 1000


def _project_exposure_graph(
    db: Session,
    *,
    now: datetime,
    coverage: TopologyCoverageOut,
    agent_nodes: dict[str, str],
) -> None:
    postures = db.execute(
        select(
            ExposureAssetPostureModel.agent_id,
            ExposureAssetPostureModel.asset_key,
            ExposureAssetPostureModel.display_name,
            ExposureAssetPostureModel.severity,
            ExposureAssetPostureModel.risk_score,
            ExposureAssetPostureModel.confidence,
            ExposureAssetPostureModel.last_seen_at,
        )
        .where(ExposureAssetPostureModel.agent_id.isnot(None))
        .order_by(ExposureAssetPostureModel.risk_score.desc())
        .limit(_MAX_EXPOSURE_ROWS)
    ).all()

    for row in postures:
        agent_id, asset_key, display_name, severity, risk_score, confidence, last_seen = row
        agent_node_key = agent_nodes.get(str(agent_id or ""))
        if not agent_node_key:
            continue

        exposure_node_key = _node_key("exposure", str(asset_key))
        sev = str(severity or "unknown")
        ts = _to_utc(last_seen) or now
        label = str(display_name or asset_key)

        repository.upsert_node(
            db,
            node_key=exposure_node_key,
            node_type="host",
            label=label,
            agent_id=str(agent_id),
            ip=None,
            cidr=None,
            port=None,
            protocol=None,
            severity=sev,
            risk_score=int(risk_score or 0),
            confidence=int(confidence or 80),
            first_seen_at=ts,
            last_seen_at=ts,
            extra_data={"exposure_asset_key": str(asset_key)},
        )

        repository.upsert_edge(
            db,
            edge_key=_edge_key("exposure_related", agent_node_key, exposure_node_key),
            source_node_key=agent_node_key,
            target_node_key=exposure_node_key,
            edge_type="exposure_related",
            agent_id=str(agent_id),
            weight=1.0,
            confidence=80,
            severity=sev,
            port=None,
            protocol=None,
            first_seen_at=ts,
            last_seen_at=ts,
            extra_data={"risk_score": int(risk_score or 0)},
        )
        coverage.exposure_edges_added += 1
