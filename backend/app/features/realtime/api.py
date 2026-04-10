from __future__ import annotations

import asyncio
import os
import time
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from app.core.config import settings
from app.core.portal_auth import PortalPrincipal, get_current_user
from app.core.realtime import PORTAL_REALTIME_REPLAY_MAX_EVENTS, load_portal_realtime_replay, read_portal_realtime_stream
from app.core.redis_client import get_redis
from app.features.realtime.schemas import StreamTokenOut
from app.features.realtime.service import (
    StreamPrincipal,
    allow_envelope_for_stream,
    available_realtime_topics,
    build_realtime_envelope,
    cursor_to_int,
    decode_stream_token,
    format_sse_chunk,
    issue_stream_token,
    parse_realtime_envelope,
    parse_requested_topics,
    resolve_stream_topics,
    topic_invalidate_event,
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


def _stream_read_block_ms() -> int:
    configured = int(getattr(settings, "NETWATCH_REALTIME_STREAM_READ_BLOCK_MS", 1000) or 1000)
    if configured < 100:
        return 100
    if configured > 5000:
        return 5000
    return configured


def _replay_delivery_max() -> int:
    raw = str(os.getenv("NETWATCH_REALTIME_REPLAY_DELIVERY_MAX", "200") or "200").strip()
    try:
        parsed = int(raw, 10)
    except Exception:
        parsed = 200
    return max(16, min(parsed, PORTAL_REALTIME_REPLAY_MAX_EVENTS))


@router.post("/token", response_model=StreamTokenOut)
def issue_stream_token_endpoint(user: PortalPrincipal = Depends(get_current_user)) -> StreamTokenOut:
    token, expires_in = issue_stream_token(user=user)
    return StreamTokenOut(stream_token=token, expires_in=expires_in)


def _invalidate_chunk(
    *,
    topic: str,
    reason: str,
    resume_from_cursor: int,
    resume_to_cursor: int,
) -> str:
    event_type = topic_invalidate_event(topic)
    envelope = build_realtime_envelope(
        event_type=event_type,
        topic=topic,
        mode="invalidate",
        cursor=str(max(0, int(resume_to_cursor or 0))),
        payload={
            "reason": str(reason or "reconcile"),
            "scope": str(topic),
            "resume_from_cursor": str(max(0, int(resume_from_cursor or 0))),
            "resume_to_cursor": str(max(0, int(resume_to_cursor or 0))),
        },
    )
    return format_sse_chunk(event=envelope.type, sse_id=envelope.cursor, data=envelope.as_json())


async def _stream_events(
    request: Request,
    *,
    principal: StreamPrincipal,
    redis_client: object,
    topics: list[str],
    replay_after_cursor: int,
) -> AsyncGenerator[str, None]:
    allowed_topics = set(topics)
    keepalive_seconds = _sse_keepalive_seconds()
    read_block_ms = _stream_read_block_ms()
    replay_cap = _replay_delivery_max()

    last_keepalive = 0.0
    last_cursor = max(0, int(replay_after_cursor or 0))
    last_stream_id = "$"

    yield format_sse_chunk(comment="stream-open")

    replay_rows = await asyncio.to_thread(
        load_portal_realtime_replay,
        redis_client,
        max_events=PORTAL_REALTIME_REPLAY_MAX_EVENTS,
    )

    if replay_rows:
        earliest_cursor = replay_rows[0].cursor
        latest_cursor = replay_rows[-1].cursor
        last_stream_id = replay_rows[-1].stream_id

        if replay_after_cursor > 0 and latest_cursor > replay_after_cursor:
            if replay_after_cursor < (earliest_cursor - 1):
                last_cursor = max(last_cursor, latest_cursor)
                for topic in topics:
                    yield _invalidate_chunk(
                        topic=topic,
                        reason="cursor_gap",
                        resume_from_cursor=replay_after_cursor,
                        resume_to_cursor=latest_cursor,
                    )
            else:
                pending = [entry for entry in replay_rows if entry.cursor > replay_after_cursor]
                if len(pending) > replay_cap:
                    last_cursor = max(last_cursor, latest_cursor)
                    for topic in topics:
                        yield _invalidate_chunk(
                            topic=topic,
                            reason="cursor_lag",
                            resume_from_cursor=replay_after_cursor,
                            resume_to_cursor=latest_cursor,
                        )
                else:
                    for entry in pending:
                        envelope = parse_realtime_envelope(entry.message)
                        if envelope is None:
                            continue
                        if not allow_envelope_for_stream(
                            envelope=envelope,
                            principal=principal,
                            allowed_topics=allowed_topics,
                        ):
                            continue
                        if entry.cursor <= last_cursor:
                            continue
                        last_cursor = entry.cursor
                        last_stream_id = entry.stream_id
                        yield format_sse_chunk(event=envelope.type, sse_id=envelope.cursor, data=envelope.as_json())

    while True:
        if await request.is_disconnected():
            break

        rows = await asyncio.to_thread(
            read_portal_realtime_stream,
            redis_client,
            last_stream_id=last_stream_id,
            block_ms=read_block_ms,
            count=100,
        )
        for entry in rows:
            last_stream_id = entry.stream_id
            if entry.cursor <= last_cursor:
                continue
            envelope = parse_realtime_envelope(entry.message)
            if envelope is None:
                continue
            if not allow_envelope_for_stream(
                envelope=envelope,
                principal=principal,
                allowed_topics=allowed_topics,
            ):
                continue
            last_cursor = entry.cursor
            yield format_sse_chunk(event=envelope.type, sse_id=envelope.cursor, data=envelope.as_json())

        now = time.monotonic()
        if now - last_keepalive >= float(keepalive_seconds):
            last_keepalive = now
            yield format_sse_chunk(comment="keepalive")


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
