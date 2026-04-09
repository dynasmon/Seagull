from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.portal_auth import get_current_user
from app.core.realtime import portal_realtime_channel
from app.core.redis_client import get_redis


router = APIRouter(
    prefix="/realtime",
    tags=["realtime"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/status")
def realtime_status() -> dict[str, object]:
    redis_available = False
    redis_client = get_redis()
    if redis_client is not None:
        try:
            redis_available = bool(redis_client.ping())
        except Exception:
            redis_available = False

    return {
        "channel": portal_realtime_channel(),
        "redis_available": redis_available,
    }
