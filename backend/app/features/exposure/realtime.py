from __future__ import annotations

from typing import Any

from app.features.exposure.models import ExposureAssetPostureModel


def project_posture_update(row: ExposureAssetPostureModel) -> dict[str, Any]:
    """Produce a compact realtime payload for an asset posture change."""
    return {
        "asset_key": row.asset_key,
        "agent_id": row.agent_id,
        "risk_score": row.risk_score,
        "severity": row.severity,
        "confidence": row.confidence,
        "status": row.status,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }
