from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.features.settings.models import PlatformSettingModel


def list_settings(db: Session) -> list[PlatformSettingModel]:
    return db.query(PlatformSettingModel).order_by(PlatformSettingModel.key.asc()).all()


def get_setting_by_key(db: Session, key: str) -> PlatformSettingModel | None:
    return db.get(PlatformSettingModel, key)


def build_setting_for_create(
    *,
    key: str,
    value: Any,
    description: str | None,
    updated_by_user_id: int,
    updated_by_username: str,
) -> PlatformSettingModel:
    now = datetime.utcnow()
    return PlatformSettingModel(
        key=key,
        value=value,
        description=description,
        created_at=now,
        updated_at=now,
        updated_by_user_id=updated_by_user_id,
        updated_by_username=updated_by_username,
    )


def apply_setting_update(
    row: PlatformSettingModel,
    *,
    value: Any,
    description: str | None,
    updated_by_user_id: int,
    updated_by_username: str,
) -> None:
    row.value = value
    row.description = description
    row.updated_at = datetime.utcnow()
    row.updated_by_user_id = updated_by_user_id
    row.updated_by_username = updated_by_username


def add(db: Session, row: PlatformSettingModel) -> None:
    db.add(row)


def delete(db: Session, row: PlatformSettingModel) -> None:
    db.delete(row)


def flush(db: Session) -> None:
    db.flush()


def refresh(db: Session, row: PlatformSettingModel) -> None:
    db.refresh(row)


def commit(db: Session) -> None:
    db.commit()


def rollback(db: Session) -> None:
    db.rollback()
