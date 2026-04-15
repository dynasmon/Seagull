from __future__ import annotations

from typing import Any

from app.features.realtime.projectors import project_response_action_lifecycle_patch
from app.features.realtime.service import publish_realtime
from app.features.response.models import ResponseActionModel, ResponseActionResultModel


def _action_mapping(row: ResponseActionModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "action_type": row.action_type,
        "agent_id": row.agent_id,
        "status": row.status,
        "requested_by": row.requested_by,
        "requested_at": row.requested_at,
        "delivered_at": row.delivered_at,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "cancelled_at": row.cancelled_at,
        "cancelled_by": row.cancelled_by,
        "last_error": row.last_error,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "expires_at": row.expires_at,
    }


def _result_mapping(row: ResponseActionResultModel | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": row.id,
        "response_action_id": row.response_action_id,
        "agent_id": row.agent_id,
        "status": row.status,
        "result_payload": row.result_payload if isinstance(row.result_payload, dict) else {},
        "error": row.error,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def publish_response_action_lifecycle(
    *,
    action: ResponseActionModel,
    lifecycle_event: str,
    result: ResponseActionResultModel | None = None,
    requires_reconcile: bool = False,
) -> None:
    payload = project_response_action_lifecycle_patch(
        lifecycle_event=lifecycle_event,
        workflow=_action_mapping(action),
        result=_result_mapping(result),
        requires_reconcile=requires_reconcile,
    )
    if not payload:
        return
    try:
        publish_realtime("ui.response_actions.lifecycle.patch", payload)
    except Exception:
        return
