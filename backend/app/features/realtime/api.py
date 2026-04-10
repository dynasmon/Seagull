from __future__ import annotations

import asyncio
import time
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.core.portal_auth import PortalPrincipal, get_current_user
from app.core.realtime import load_portal_realtime_replay, portal_realtime_channel
from app.core.redis_client import get_redis
from app.features.realtime.schemas import RealtimeEnvelope, StreamTokenOut
from app.features.realtime.service import (
    available_realtime_topics,
    cursor_to_int,
    envelope_cursor_to_int,
    allow_envelope_for_stream,
    decode_stream_token,
    format_sse_chunk,
    issue_stream_token,
    parse_requested_topics,
    parse_realtime_envelope,
    resolve_stream_topics,
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
    topics: list[str],
    replay_after_cursor: int,
) -> AsyncGenerator[str, None]:
    channels = [portal_realtime_channel(topic) for topic in topics]
    allowed_topics = set(topics)
    pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
    keepalive_seconds = _sse_keepalive_seconds()
    last_keepalive = 0.0
    last_cursor = max(0, int(replay_after_cursor or 0))
    subscription_ready = False

    try:
        await asyncio.to_thread(pubsub.subscribe, *channels)
        subscription_ready = True
        yield format_sse_chunk(comment="stream-open")

        replay = await _load_replay_envelopes(
            redis_client=redis_client,
            topics=topics,
            after_cursor=last_cursor,
        )
        for envelope in replay:
            cursor = envelope_cursor_to_int(envelope)
            if cursor <= last_cursor:
                continue
            if not allow_envelope_for_stream(
                envelope=envelope,
                principal=principal,
                allowed_topics=allowed_topics,
            ):
                continue
            last_cursor = cursor
            yield format_sse_chunk(event=envelope.type, sse_id=envelope.cursor, data=envelope.as_json())

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
                if envelope is None:
                    continue
                cursor = envelope_cursor_to_int(envelope)
                if cursor <= last_cursor:
                    continue
                if not allow_envelope_for_stream(
                    envelope=envelope,
                    principal=principal,
                    allowed_topics=allowed_topics,
                ):
                    continue
                last_cursor = cursor
                yield format_sse_chunk(event=envelope.type, sse_id=envelope.cursor, data=envelope.as_json())

            now = time.monotonic()
            if now - last_keepalive >= float(keepalive_seconds):
                last_keepalive = now
                yield format_sse_chunk(comment="keepalive")
    except asyncio.CancelledError:
        raise
    finally:
        if subscription_ready:
            try:
                await asyncio.to_thread(pubsub.unsubscribe, *channels)
            except Exception:
                pass
        try:
            await asyncio.to_thread(pubsub.close)
        except Exception:
            pass


async def _load_replay_envelopes(
    *,
    redis_client: object,
    topics: list[str],
    after_cursor: int,
) -> list[RealtimeEnvelope]:
    out: list[RealtimeEnvelope] = []
    for topic in topics:
        rows = await asyncio.to_thread(load_portal_realtime_replay, redis_client, topic=topic, max_events=200)
        for row in rows:
            envelope = parse_realtime_envelope(row)
            if envelope is None:
                continue
            if envelope_cursor_to_int(envelope) <= int(after_cursor or 0):
                continue
            out.append(envelope)
    out.sort(key=envelope_cursor_to_int)
    return out


@router.get("/portal")
async def portal_stream_endpoint(
    request: Request,
    st: str = Query(..., min_length=1, max_length=4096, description="Short-lived stream token"),
    topics: str | None = Query(None, min_length=1, max_length=256, description="CSV of requested realtime topics"),
    cursor: str | None = Query(None, min_length=1, max_length=64, description="Last processed cursor for replay"),
):
    try:
        principal = decode_stream_token(st)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid stream token")

    requested_topics = parse_requested_topics(topics)
    if not requested_topics:
        requested_topics = list(available_realtime_topics())
    resolved_topics = resolve_stream_topics(principal=principal, requested_topics=requested_topics)
    if not resolved_topics:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No realtime topics allowed")

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
        _stream_events(
            request,
            principal=principal,
            redis_client=redis_client,
            topics=resolved_topics,
            replay_after_cursor=cursor_to_int(cursor),
        ),
        media_type="text/event-stream",
        headers=headers,
    )
