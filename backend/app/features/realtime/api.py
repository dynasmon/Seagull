from __future__ import annotations

import asyncio
import time
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.core.portal_auth import PortalPrincipal, get_current_user
from app.core.realtime import portal_realtime_channel
from app.core.redis_client import get_redis
from app.features.realtime.schemas import StreamTokenOut
from app.features.realtime.service import (
    allow_envelope_for_stream,
    decode_stream_token,
    format_sse_chunk,
    issue_stream_token,
    parse_realtime_envelope,
    StreamPrincipal,
)


router = APIRouter(
    prefix="/realtime",
    tags=["realtime"],
)


def _sse_keepalive_seconds() -> int:
    configured = int(getattr(settings, "NETWATCH_REALTIME_SSE_KEEPALIVE_SECONDS", 15) or 15)
    if configured < 5:
        return 5
    if configured > 60:
        return 60
    return configured


@router.post("/token", response_model=StreamTokenOut)
def issue_stream_token_endpoint(user: PortalPrincipal = Depends(get_current_user)) -> StreamTokenOut:
    token, expires_in = issue_stream_token(user=user)
    return StreamTokenOut(stream_token=token, expires_in=expires_in)


async def _stream_events(
    request: Request,
    *,
    principal: StreamPrincipal,
    redis_client: object,
) -> AsyncGenerator[str, None]:
    channel = portal_realtime_channel()
    pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
    keepalive_seconds = _sse_keepalive_seconds()
    last_keepalive = 0.0
    subscription_ready = False

    try:
        await asyncio.to_thread(pubsub.subscribe, channel)
        subscription_ready = True
        yield format_sse_chunk(comment="stream-open")
        while True:
            if await request.is_disconnected():
                break

            message = await asyncio.to_thread(pubsub.get_message, True, 1.0)
            if message and str(message.get("type") or "") == "message":
                raw_payload = message.get("data")
                if not isinstance(raw_payload, str):
                    try:
                        raw_payload = str(raw_payload or "")
                    except Exception:
                        raw_payload = ""
                envelope = parse_realtime_envelope(raw_payload)
                if envelope is not None and allow_envelope_for_stream(envelope=envelope, principal=principal):
                    yield format_sse_chunk(event=envelope.type, data=envelope.as_json())

            now = time.monotonic()
            if now - last_keepalive >= float(keepalive_seconds):
                last_keepalive = now
                yield format_sse_chunk(comment="keepalive")
    except asyncio.CancelledError:
        raise
    finally:
        if subscription_ready:
            try:
                await asyncio.to_thread(pubsub.unsubscribe, channel)
            except Exception:
                pass
        try:
            await asyncio.to_thread(pubsub.close)
        except Exception:
            pass


@router.get("/portal")
async def portal_stream_endpoint(
    request: Request,
    st: str = Query(..., min_length=1, max_length=4096, description="Short-lived stream token"),
):
    try:
        principal = decode_stream_token(st)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid stream token")
    redis_client = get_redis(decode_responses=True)
    if redis_client is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Realtime unavailable")

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "Pragma": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(
        _stream_events(request, principal=principal, redis_client=redis_client),
        media_type="text/event-stream",
        headers=headers,
    )
