from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.core.db import get_db
from app.core.db.session import managed_session
from app.features.auth.session import PortalPrincipal, require_admin
from app.features.detections.rules.sigma_export import export_pack_sigma_yaml
from app.features.detections.testing import run_detection_backtest, validate_detection_content

MAX_BACKTEST_LIMIT = 5000
MAX_BACKTEST_SAMPLE_LIMIT = 10
MAX_BACKTEST_RANGE_DAYS = 31


class DetectionValidationRequest(BaseModel):
    include_disabled: bool = True
    apply_env_filters: bool = False
    execute_yaml_tests: bool = True


class DetectionBacktestRequest(BaseModel):
    rule_id: str = Field(..., min_length=1, max_length=128)
    started_at: datetime
    ended_at: datetime
    limit: int = Field(1000, ge=1, le=MAX_BACKTEST_LIMIT)
    sample_limit: int = Field(5, ge=1, le=MAX_BACKTEST_SAMPLE_LIMIT)
    dry_run: bool = True


router = APIRouter(
    prefix="/detections",
    tags=["detections"],
    dependencies=[Depends(require_admin)],
)


@router.post("/validate")
def validate_detections_endpoint(
    payload: DetectionValidationRequest,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    with managed_session(db) as db_session:
        report = validate_detection_content(
            include_disabled=payload.include_disabled,
            apply_env_filters=payload.apply_env_filters,
            execute_yaml_tests=payload.execute_yaml_tests,
        )
        write_audit_event(
            db_session,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="detection.validate",
            resource_type="detection_content",
            resource_id=None,
            outcome="success",
            after={
                "passed": report["passed"],
                "rule_count": report["rule_count"],
                "error_count": report["error_count"],
                "warning_count": report["warning_count"],
                "yaml_failed_count": report["yaml_failed_count"],
            },
            context=payload.model_dump(),
        )
        db_session.commit()
        return report


@router.post("/backtest")
def backtest_detection_endpoint(
    payload: DetectionBacktestRequest,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if payload.started_at >= payload.ended_at:
        raise HTTPException(status_code=400, detail="started_at must be before ended_at")
    if (payload.ended_at - payload.started_at) > timedelta(days=MAX_BACKTEST_RANGE_DAYS):
        raise HTTPException(status_code=400, detail="backtest range exceeds safe limit")

    with managed_session(db) as db_session:
        try:
            result = run_detection_backtest(
                db_session,
                rule_id=payload.rule_id,
                started_at=payload.started_at,
                ended_at=payload.ended_at,
                limit=payload.limit,
                sample_limit=payload.sample_limit,
                dry_run=payload.dry_run,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        write_audit_event(
            db_session,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="detection.backtest",
            resource_type="detection_rule",
            resource_id=payload.rule_id,
            outcome="success",
            after={
                "dry_run": bool(payload.dry_run),
                "match_count": result["match_count"],
                "scanned_events": result["scanned_events"],
                "truncated": result["truncated"],
            },
            context={
                "started_at": payload.started_at.isoformat(),
                "ended_at": payload.ended_at.isoformat(),
                "limit": payload.limit,
                "sample_limit": payload.sample_limit,
            },
        )
        db_session.commit()
        return result


@router.get("/export/sigma")
def export_sigma_endpoint(
    pack: str,
    include_disabled: bool = False,
    admin: PortalPrincipal = Depends(require_admin),
) -> Response:
    yaml_text = export_pack_sigma_yaml(pack=pack, include_disabled=include_disabled)
    return Response(content=yaml_text, media_type="application/x-yaml")
