from __future__ import annotations

import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.audit import audit_actor, write_audit_event
from app.core.db import SessionLocal
from app.core.portal_auth import PortalPrincipal, require_admin
from app.models.platform_settings import PlatformSettingModel
from app.schemas.settings import PlatformSettingOut, PlatformSettingUpsertIn


router = APIRouter(prefix="/settings", tags=["settings"], dependencies=[Depends(require_admin)])

_KEY_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
_DENY_SENSITIVE_KEY_RE = re.compile(r"(password|secret|token|private|credential|jwt|pepper|key)", re.IGNORECASE)


def _to_out(row: PlatformSettingModel) -> PlatformSettingOut:
    return PlatformSettingOut(
        key=row.key,
        value=row.value,
        description=row.description,
        created_at=row.created_at,
        updated_at=row.updated_at,
        updated_by_user_id=row.updated_by_user_id,
        updated_by_username=row.updated_by_username,
    )


def _validate_key(key: str) -> str:
    k = (key or "").strip().lower()
    if not _KEY_RE.match(k):
        raise HTTPException(status_code=422, detail="Invalid setting key format")
    if _DENY_SENSITIVE_KEY_RE.search(k):
        raise HTTPException(status_code=422, detail="Sensitive setting keys are not allowed in this endpoint")
    return k


@router.get("", response_model=list[PlatformSettingOut])
def list_platform_settings(_: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        rows = db.query(PlatformSettingModel).order_by(PlatformSettingModel.key.asc()).all()
        return [_to_out(r) for r in rows]
    finally:
        db.close()


@router.put("/{key}", response_model=PlatformSettingOut)
def upsert_platform_setting(
    key: str,
    payload: PlatformSettingUpsertIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
):
    db = SessionLocal()
    try:
        skey = _validate_key(key)
        row = db.get(PlatformSettingModel, skey)
        before = {}
        if row is None:
            row = PlatformSettingModel(
                key=skey,
                value=payload.value,
                description=(payload.description or None),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                updated_by_user_id=admin.id,
                updated_by_username=admin.username,
            )
            action = "settings.create"
        else:
            before = {"key": row.key, "value": row.value, "description": row.description}
            row.value = payload.value
            row.description = (payload.description or None)
            row.updated_at = datetime.utcnow()
            row.updated_by_user_id = admin.id
            row.updated_by_username = admin.username
            action = "settings.update"

        db.add(row)
        db.flush()
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action=action,
            resource_type="platform_setting",
            resource_id=row.key,
            outcome="success",
            before=before,
            after={"key": row.key, "value": row.value, "description": row.description},
            reason=payload.reason,
        )
        db.commit()
        db.refresh(row)
        return _to_out(row)
    finally:
        db.close()


@router.delete("/{key}", status_code=status.HTTP_204_NO_CONTENT)
def delete_platform_setting(key: str, request: Request, admin: PortalPrincipal = Depends(require_admin)):
    db = SessionLocal()
    try:
        skey = _validate_key(key)
        row = db.get(PlatformSettingModel, skey)
        if row is None:
            raise HTTPException(status_code=404, detail="Setting not found")

        before = {"key": row.key, "value": row.value, "description": row.description}
        db.delete(row)
        write_audit_event(
            db,
            request=request,
            actor=audit_actor(admin.id, admin.username),
            event_type="admin_action",
            action="settings.delete",
            resource_type="platform_setting",
            resource_id=skey,
            outcome="success",
            before=before,
            after={},
        )
        db.commit()
        return None
    finally:
        db.close()
