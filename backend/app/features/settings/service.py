from __future__ import annotations

import re

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.audit import audit_actor, write_audit_event
from app.features.auth.session import PortalPrincipal
from app.features.settings.models import PlatformSettingModel
from app.features.settings.repository import (
    add,
    apply_setting_update,
    build_setting_for_create,
    commit,
    delete,
    flush,
    get_setting_by_key,
    list_settings,
    refresh,
)
from app.features.settings.schemas import PlatformSettingOut, PlatformSettingUpsertIn


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


def validate_key(key: str) -> str:
    normalized = (key or "").strip().lower()
    if not _KEY_RE.match(normalized):
        raise HTTPException(status_code=422, detail="Invalid setting key format")
    if _DENY_SENSITIVE_KEY_RE.search(normalized):
        raise HTTPException(status_code=422, detail="Sensitive setting keys are not allowed in this endpoint")
    return normalized


def list_platform_settings(db: Session) -> list[PlatformSettingOut]:
    rows = list_settings(db)
    return [_to_out(row) for row in rows]


def upsert_platform_setting(
    db: Session,
    *,
    key: str,
    payload: PlatformSettingUpsertIn,
    request: Request,
    admin: PortalPrincipal,
) -> PlatformSettingOut:
    skey = validate_key(key)
    row = get_setting_by_key(db, skey)
    before: dict = {}

    if row is None:
        row = build_setting_for_create(
            key=skey,
            value=payload.value,
            description=(payload.description or None),
            updated_by_user_id=admin.id,
            updated_by_username=admin.username,
        )
        action = "settings.create"
    else:
        before = {"key": row.key, "value": row.value, "description": row.description}
        apply_setting_update(
            row,
            value=payload.value,
            description=(payload.description or None),
            updated_by_user_id=admin.id,
            updated_by_username=admin.username,
        )
        action = "settings.update"

    add(db, row)
    flush(db)
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
    commit(db)
    refresh(db, row)
    return _to_out(row)


def delete_platform_setting(db: Session, *, key: str, request: Request, admin: PortalPrincipal) -> None:
    skey = validate_key(key)
    row = get_setting_by_key(db, skey)
    if row is None:
        raise HTTPException(status_code=404, detail="Setting not found")

    before = {"key": row.key, "value": row.value, "description": row.description}
    delete(db, row)
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
    commit(db)
