from __future__ import annotations

import asyncio
import logging
import time
from typing import AsyncGenerator, Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, status
from fastapi.responses import StreamingResponse
from starlette.websockets import WebSocketDisconnect, WebSocketState

from app.core.config import settings
from app.core.observability import incr_counter, log_event
from app.features.auth.session import PortalPrincipal, get_current_user
from app.core.realtime import (
    PORTAL_REALTIME_REPLAY_MAX_EVENTS,
    PortalRealtimeStreamEntry,
    load_portal_realtime_replay_window,
    read_portal_realtime_stream,
)
from app.core.cache import get_redis
from app.features.realtime.schemas import RealtimeEnvelope, StreamTokenOut
from app.features.realtime.service import (
    StreamPrincipal,
    allow_envelope_for_stream,
    build_realtime_envelope,
    coalesce_realtime_envelopes,
    cursor_to_int,
    decode_stream_token,
    format_sse_chunk,
    issue_stream_token,
    parse_realtime_envelope,
    parse_requested_topics,
    resolve_stream_topics,
    topic_invalidate_event,
)

logger = logging.getLogger("seagull.api.realtime")

router = APIRouter(
    prefix="/realtime",
    tags=["realtime"],
)


def _sse_keepalive_seconds() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_SSE_KEEPALIVE_SECONDS", 15) or 15)
    if configured < 5:
        return 5
    if configured > 60:
        return 60
    return configured


def _ws_keepalive_seconds() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_WS_KEEPALIVE_SECONDS", 20) or 20)
    if configured < 5:
        return 5
    if configured > 60:
        return 60
    return configured


def _stream_read_block_ms() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_STREAM_READ_BLOCK_MS", 200) or 200)
    if configured < 100:
        return 100
    if configured > 5000:
        return 5000
    return configured


def _replay_delivery_max() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_REPLAY_DELIVERY_MAX", 200) or 200)
    return max(16, min(configured, PORTAL_REALTIME_REPLAY_MAX_EVENTS))


@router.post("/token", response_model=StreamTokenOut)
def issue_stream_token_endpoint(user: PortalPrincipal = Depends(get_current_user)) -> StreamTokenOut:
    token, expires_in = issue_stream_token(user=user)
    return StreamTokenOut(stream_token=token, expires_in=expires_in)


def _build_invalidate_envelope(
    *,
    topic: str,
    reason: str,
    resume_from_cursor: int,
    resume_to_cursor: int,
) -> RealtimeEnvelope:
    event_type = topic_invalidate_event(topic)
    return build_realtime_envelope(
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


def _record_stream_attempt(*, transport: str, outcome: str, topics: list[str] | None = None, detail: str | None = None) -> None:
    incr_counter("realtime_stream_connections_total", transport=transport, outcome=outcome)
    if outcome != "accepted":
        log_event(
            logger,
            "warning",
            "realtime_stream_rejected",
            transport=transport,
            outcome=outcome,
            topics=",".join(topics or ()),
            detail=detail or "",
        )


def _record_stream_open(*, transport: str, topics: list[str], replay_after_cursor: int) -> None:
    incr_counter("realtime_stream_connections_total", transport=transport, outcome="opened")
    if replay_after_cursor > 0:
        incr_counter("realtime_stream_reconnect_total", transport=transport)
    log_event(
        logger,
        "info",
        "realtime_stream_opened",
        transport=transport,
        topics=",".join(topics),
        replay_after_cursor=max(0, int(replay_after_cursor or 0)),
    )


def _record_stream_close(*, transport: str, reason: str) -> None:
    incr_counter("realtime_stream_disconnect_total", transport=transport, reason=reason)
    log_event(logger, "info", "realtime_stream_closed", transport=transport, reason=reason)


def _record_replay_failure(*, reason: str, topics: list[str], replay_after_cursor: int, resume_to_cursor: int) -> None:
    incr_counter("realtime_cursor_gap_total", reason=reason)
    log_event(
        logger,
        "warning",
        "realtime_replay_reconcile_required",
        reason=reason,
        topics=",".join(topics),
        replay_after_cursor=max(0, int(replay_after_cursor or 0)),
        resume_to_cursor=max(0, int(resume_to_cursor or 0)),
    )


def _filter_delivery_batch(
    *,
    entries: list[PortalRealtimeStreamEntry],
    principal: StreamPrincipal,
    allowed_topics: set[str],
    min_cursor_exclusive: int,
) -> tuple[list[RealtimeEnvelope], int]:
    envelopes: list[RealtimeEnvelope] = []
    max_cursor = max(0, int(min_cursor_exclusive or 0))

    for entry in entries:
        if entry.cursor > max_cursor:
            max_cursor = entry.cursor
        if entry.cursor <= min_cursor_exclusive:
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
        envelopes.append(envelope)

    return coalesce_realtime_envelopes(envelopes), max_cursor


async def _iter_stream_batches(
    *,
    disconnect_check: Callable[[], Awaitable[bool]],
    principal: StreamPrincipal,
    redis_client: object,
    topics: list[str],
    replay_after_cursor: int,
) -> AsyncGenerator[list[RealtimeEnvelope], None]:
    allowed_topics = set(topics)
    read_block_ms = _stream_read_block_ms()
    replay_cap = _replay_delivery_max()

    last_cursor = max(0, int(replay_after_cursor or 0))
    last_stream_id = "$"

    replay_window = await asyncio.to_thread(
        load_portal_realtime_replay_window,
        redis_client,
        max_events=PORTAL_REALTIME_REPLAY_MAX_EVENTS,
    )

    if replay_window.entries:
        last_stream_id = replay_window.entries[-1].stream_id
        if replay_after_cursor > 0 and replay_window.latest_cursor > replay_after_cursor:
            if replay_after_cursor < (replay_window.earliest_cursor - 1):
                _record_replay_failure(
                    reason="cursor_gap",
                    topics=topics,
                    replay_after_cursor=replay_after_cursor,
                    resume_to_cursor=replay_window.latest_cursor,
                )
                last_cursor = max(last_cursor, replay_window.latest_cursor)
                yield [
                    _build_invalidate_envelope(
                        topic=topic,
                        reason="cursor_gap",
                        resume_from_cursor=replay_after_cursor,
                        resume_to_cursor=replay_window.latest_cursor,
                    )
                    for topic in topics
                ]
            else:
                pending = [entry for entry in replay_window.entries if entry.cursor > replay_after_cursor]
                if len(pending) > replay_cap:
                    _record_replay_failure(
                        reason="replay_overflow",
                        topics=topics,
                        replay_after_cursor=replay_after_cursor,
                        resume_to_cursor=replay_window.latest_cursor,
                    )
                    last_cursor = max(last_cursor, replay_window.latest_cursor)
                    yield [
                        _build_invalidate_envelope(
                            topic=topic,
                            reason="replay_overflow",
                            resume_from_cursor=replay_after_cursor,
                            resume_to_cursor=replay_window.latest_cursor,
                        )
                        for topic in topics
                    ]
                else:
                    replay_batch, replay_cursor = _filter_delivery_batch(
                        entries=pending,
                        principal=principal,
                        allowed_topics=allowed_topics,
                        min_cursor_exclusive=last_cursor,
                    )
                    last_cursor = max(last_cursor, replay_cursor)
                    if replay_batch:
                        yield replay_batch

    while True:
        if await disconnect_check():
            break

        rows = await asyncio.to_thread(
            read_portal_realtime_stream,
            redis_client,
            last_stream_id=last_stream_id,
            block_ms=read_block_ms,
            count=100,
        )
        if rows:
            last_stream_id = rows[-1].stream_id
            batch, batch_cursor = _filter_delivery_batch(
                entries=rows,
                principal=principal,
                allowed_topics=allowed_topics,
                min_cursor_exclusive=last_cursor,
            )
            last_cursor = max(last_cursor, batch_cursor)
            yield batch
            continue

        yield []


async def _request_is_disconnected(request: Request) -> bool:
    return await request.is_disconnected()


async def _websocket_is_disconnected(websocket: WebSocket) -> bool:
    return (
        websocket.application_state == WebSocketState.DISCONNECTED
        or websocket.client_state == WebSocketState.DISCONNECTED
    )


def _resolve_sse_replay_after_cursor(*, request: Request, cursor: str | None) -> int:
    query_cursor = cursor_to_int(cursor)
    header_cursor = cursor_to_int(request.headers.get("last-event-id"))
    return max(query_cursor, header_cursor)


def _resolve_stream_session(*, stream_token: str, topics: str | None, transport: str) -> tuple[StreamPrincipal, list[str], object]:
    try:
        principal = decode_stream_token(stream_token)
    except ValueError as exc:
        _record_stream_attempt(transport=transport, outcome="invalid_token", detail="invalid stream token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid stream token") from exc

    requested_topics = parse_requested_topics(topics)
    resolved_topics = resolve_stream_topics(principal=principal, requested_topics=requested_topics)
    rejected_topics = [topic for topic in requested_topics if topic not in resolved_topics]
    if rejected_topics:
        incr_counter("realtime_unauthorized_topic_total", transport=transport)
        log_event(
            logger,
            "warning",
            "realtime_unauthorized_topics",
            transport=transport,
            username=principal.username,
            requested_topics=",".join(requested_topics),
            rejected_topics=",".join(rejected_topics),
        )
    if not resolved_topics:
        _record_stream_attempt(
            transport=transport,
            outcome="unauthorized_topic",
            topics=requested_topics,
            detail="no realtime topics allowed",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No realtime topics allowed")

    redis_client = get_redis(decode_responses=True)
    if redis_client is None:
        _record_stream_attempt(
            transport=transport,
            outcome="redis_unavailable",
            topics=resolved_topics,
            detail="redis unavailable",
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Realtime unavailable")

    _record_stream_attempt(transport=transport, outcome="accepted", topics=resolved_topics)
    return principal, resolved_topics, redis_client


async def _stream_events(
    request: Request,
    *,
    principal: StreamPrincipal,
    redis_client: object,
    topics: list[str],
    replay_after_cursor: int,
    transport: str,
) -> AsyncGenerator[str, None]:
    keepalive_seconds = _sse_keepalive_seconds()
    last_keepalive = time.monotonic()

    _record_stream_open(transport=transport, topics=topics, replay_after_cursor=replay_after_cursor)
    yield format_sse_chunk(comment="stream-open")

    try:
        async for batch in _iter_stream_batches(
            disconnect_check=lambda: _request_is_disconnected(request),
            principal=principal,
            redis_client=redis_client,
            topics=topics,
            replay_after_cursor=replay_after_cursor,
        ):
            if batch:
                for envelope in batch:
                    yield format_sse_chunk(event=envelope.type, sse_id=envelope.cursor, data=envelope.as_json())
                last_keepalive = time.monotonic()
                continue

            now = time.monotonic()
            if now - last_keepalive >= float(keepalive_seconds):
                last_keepalive = now
                yield format_sse_chunk(comment="keepalive")
    except asyncio.CancelledError:
        _record_stream_close(transport=transport, reason="cancelled")
        raise
    except Exception as exc:
        _record_stream_close(transport=transport, reason=type(exc).__name__)
        raise
    else:
        _record_stream_close(transport=transport, reason="client_disconnect")


@router.get("/portal")
async def portal_stream_endpoint(
    request: Request,
    st: str = Query(..., min_length=1, max_length=4096, description="Short-lived stream token"),
    topics: str | None = Query(None, min_length=1, max_length=256, description="CSV of requested realtime topics"),
    cursor: str | None = Query(None, min_length=1, max_length=64, description="Last processed cursor for replay"),
):
    principal, resolved_topics, redis_client = _resolve_stream_session(stream_token=st, topics=topics, transport="sse")

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
            replay_after_cursor=_resolve_sse_replay_after_cursor(request=request, cursor=cursor),
            transport="sse",
        ),
        media_type="text/event-stream",
        headers=headers,
    )


@router.websocket("/portal/ws")
async def portal_websocket_endpoint(websocket: WebSocket) -> None:
    stream_token = str(websocket.query_params.get("st") or "").strip()
    topics = websocket.query_params.get("topics")
    cursor = websocket.query_params.get("cursor")

    await websocket.accept()

    try:
        principal, resolved_topics, redis_client = _resolve_stream_session(stream_token=stream_token, topics=topics, transport="ws")
    except HTTPException as exc:
        close_code = status.WS_1008_POLICY_VIOLATION if exc.status_code in {401, 403} else 1013
        await websocket.close(code=close_code, reason=str(exc.detail))
        return

    _record_stream_open(transport="ws", topics=resolved_topics, replay_after_cursor=cursor_to_int(cursor))

    keepalive_seconds = _ws_keepalive_seconds()
    last_keepalive = time.monotonic()

    try:
        async for batch in _iter_stream_batches(
            disconnect_check=lambda: _websocket_is_disconnected(websocket),
            principal=principal,
            redis_client=redis_client,
            topics=resolved_topics,
            replay_after_cursor=cursor_to_int(cursor),
        ):
            if batch:
                for envelope in batch:
                    await websocket.send_text(envelope.as_json())
                last_keepalive = time.monotonic()
                continue

            now = time.monotonic()
            if now - last_keepalive >= float(keepalive_seconds):
                last_keepalive = now
                await websocket.send_text('{"kind":"keepalive","transport":"ws"}')
    except WebSocketDisconnect:
        _record_stream_close(transport="ws", reason="client_disconnect")
        return
    except RuntimeError:
        _record_stream_close(transport="ws", reason="runtime_error")
        return
    except Exception as exc:
        _record_stream_close(transport="ws", reason=type(exc).__name__)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
        raise
    else:
        _record_stream_close(transport="ws", reason="client_disconnect")
