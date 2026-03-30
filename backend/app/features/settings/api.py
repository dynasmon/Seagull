from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.portal_auth import PortalPrincipal, require_admin
from app.features.settings.schemas import PlatformSettingOut, PlatformSettingUpsertIn
from app.features.settings.service import (
    delete_platform_setting as delete_platform_setting_service,
    list_platform_settings as list_platform_settings_service,
    upsert_platform_setting as upsert_platform_setting_service,
)


router = APIRouter(prefix="/settings", tags=["settings"])

@router.get("", response_model=list[PlatformSettingOut])
def list_platform_settings_endpoint(
    _: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return list_platform_settings_service(db)


@router.put("/{key}", response_model=PlatformSettingOut)
def upsert_platform_setting(
    key: str,
    payload: PlatformSettingUpsertIn,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return upsert_platform_setting_service(
        db,
        key=key,
        payload=payload,
        request=request,
        admin=admin,
    )


@router.delete("/{key}", status_code=status.HTTP_204_NO_CONTENT)
def delete_platform_setting_endpoint(
    key: str,
    request: Request,
    admin: PortalPrincipal = Depends(require_admin),
    db: Session = Depends(get_db),
):
    delete_platform_setting_service(db, key=key, request=request, admin=admin)
    return None
