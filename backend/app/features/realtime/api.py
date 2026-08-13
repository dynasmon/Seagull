from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import AsyncGenerator, Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, status
from fastapi.responses import StreamingResponse
from starlette.websockets import WebSocketDisconnect, WebSocketState

from app.core.cache import get_redis
from app.core.config import settings
from app.core.observability import incr_counter, log_event
from app.core.realtime import (
    PORTAL_REALTIME_REPLAY_MAX_EVENTS,
    ConnectionAdmission,
    PortalRealtimeConnectionLedger,
    PortalRealtimeStreamEntry,
    PortalRealtimeStreamUnavailable,
    load_portal_realtime_replay_state,
    partitions_for_topics,
    read_portal_realtime_stream,
    realtime_drain,
)
from app.core.security.rate_limit import rate_limit
from app.features.auth.session import PortalPrincipal, get_current_user
from app.features.realtime.dashboards import record_dashboard_invalidate_delivery
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

REALTIME_CONCURRENCY_LIMIT_DETAIL = "Realtime connection limit reached"
REALTIME_DRAINING_DETAIL = "Realtime server draining"
REALTIME_DRAIN_CLOSE_REASON = "Realtime server going away"
REALTIME_DRAIN_SIGNAL_JSON = '{"kind":"drain"}'
REALTIME_PING_TIMEOUT_CLOSE_REASON = "ping timeout"
REALTIME_PING_TIMEOUT_CLOSE_CODE = 1011
_TOKEN_ISSUE_RATE_LIMIT = 60
_TOKEN_ISSUE_RATE_WINDOW_SECONDS = 60


def _connection_ledger(redis_client: object) -> PortalRealtimeConnectionLedger:
    return PortalRealtimeConnectionLedger(
        redis_client,
        max_connections_per_user=int(getattr(settings, "SEAGULL_REALTIME_MAX_CONNECTIONS_PER_USER", 8) or 8),
        connection_ttl_seconds=int(getattr(settings, "SEAGULL_REALTIME_CONNECTION_TTL_SECONDS", 60) or 60),
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


def _ws_ping_enabled() -> bool:
    return bool(getattr(settings, "SEAGULL_REALTIME_WS_PING_ENABLED", True))


def _ws_ping_interval_seconds() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_WS_PING_INTERVAL_SECONDS", 20) or 20)
    if configured < 10:
        return 10
    if configured > 60:
        return 60
    return configured


def _ws_pong_timeout_seconds() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_WS_PONG_TIMEOUT_SECONDS", 10) or 10)
    if configured < 3:
        return 3
    if configured > 30:
        return 30
    return configured


def _is_ws_pong_signal(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(parsed, dict) and parsed.get("kind") == "pong"


async def _ws_pong_reader(websocket: WebSocket, liveness: dict) -> None:
    try:
        while True:
            text = await websocket.receive_text()
            if _is_ws_pong_signal(text):
                liveness["last_pong"] = time.monotonic()
    except (WebSocketDisconnect, RuntimeError, OSError):
        liveness["disconnected"] = True
    except Exception as exc:
        log_event(
            logger,
            "warning",
            "realtime_ws_pong_reader_unexpected_error",
            error_type=type(exc).__name__,
            error=str(exc),
        )
        liveness["disconnected"] = True


def _backplane_grace_seconds() -> float:
    configured = float(getattr(settings, "SEAGULL_REALTIME_BACKPLANE_GRACE_SECONDS", 5.0) or 5.0)
    if configured < 1.0:
        return 1.0
    if configured > 60.0:
        return 60.0
    return configured


def _replay_delivery_max() -> int:
    configured = int(getattr(settings, "SEAGULL_REALTIME_REPLAY_DELIVERY_MAX", 200) or 200)
    return max(16, min(configured, PORTAL_REALTIME_REPLAY_MAX_EVENTS))


@router.post("/token", response_model=StreamTokenOut)
def issue_stream_token_endpoint(user: PortalPrincipal = Depends(get_current_user)) -> StreamTokenOut:
    decision = rate_limit(
        "realtime-token",
        "user",
        str(int(user.id)),
        limit=_TOKEN_ISSUE_RATE_LIMIT,
        window_seconds=_TOKEN_ISSUE_RATE_WINDOW_SECONDS,
    )
    if not decision.allowed:
        incr_counter("realtime_connection_rejected_total", transport="token", reason="rate_limited")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many realtime token requests. Try again shortly.",
        )
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

    delivered = coalesce_realtime_envelopes(envelopes)
    for envelope in delivered:
        record_dashboard_invalidate_delivery(envelope)
    return delivered, max_cursor


async def _iter_stream_batches(
    *,
    disconnect_check: Callable[[], Awaitable[bool]],
    principal: StreamPrincipal,
    redis_client: object,
    topics: list[str],
    replay_after_cursor: int,
    transport: str,
) -> AsyncGenerator[list[RealtimeEnvelope], None]:
    allowed_topics = set(topics)
    read_block_ms = _stream_read_block_ms()
    replay_cap = _replay_delivery_max()

    last_cursor = max(0, int(replay_after_cursor or 0))
    partitions = partitions_for_topics(topics)

    replay_window, last_stream_ids = await asyncio.to_thread(
        load_portal_realtime_replay_state,
        redis_client,
        partitions=partitions,
        max_events=PORTAL_REALTIME_REPLAY_MAX_EVENTS,
    )

    if replay_window.entries:
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

    backplane_failing_since = 0.0
    while True:
        if await disconnect_check():
            break

        try:
            rows, advanced_ids = await asyncio.to_thread(
                read_portal_realtime_stream,
                redis_client,
                streams=last_stream_ids,
                block_ms=read_block_ms,
                count=100,
                raise_on_error=True,
            )
        except PortalRealtimeStreamUnavailable:
            now = time.monotonic()
            if backplane_failing_since <= 0.0:
                backplane_failing_since = now
            elif now - backplane_failing_since >= _backplane_grace_seconds():
                incr_counter("realtime_backplane_unavailable_total", transport=transport)
                log_event(
                    logger,
                    "warning",
                    "realtime_backplane_unavailable",
                    transport=transport,
                    topics=",".join(topics),
                )
                break
            await asyncio.sleep(read_block_ms / 1000.0)
            continue

        backplane_failing_since = 0.0
        if rows:
            last_stream_ids.update(advanced_ids)
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


def _resolve_stream_session(
    *, stream_token: str, topics: str | None, transport: str
) -> tuple[StreamPrincipal, list[str], object, ConnectionAdmission]:
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

    if realtime_drain.is_draining():
        incr_counter("realtime_connection_rejected_total", transport=transport, reason="draining")
        _record_stream_attempt(
            transport=transport,
            outcome="draining",
            topics=resolved_topics,
            detail="server draining",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=REALTIME_DRAINING_DETAIL,
        )

    admission = _connection_ledger(redis_client).admit(user_id=principal.user_id)
    if not admission.admitted:
        incr_counter("realtime_connection_rejected_total", transport=transport, reason="concurrency_limit")
        _record_stream_attempt(
            transport=transport,
            outcome="concurrency_limit",
            topics=resolved_topics,
            detail="connection limit reached",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=REALTIME_CONCURRENCY_LIMIT_DETAIL,
        )

    _record_stream_attempt(transport=transport, outcome="accepted", topics=resolved_topics)
    return principal, resolved_topics, redis_client, admission


async def _stream_events(
    request: Request,
    *,
    principal: StreamPrincipal,
    redis_client: object,
    topics: list[str],
    replay_after_cursor: int,
    transport: str,
    admission: ConnectionAdmission,
) -> AsyncGenerator[str, None]:
    keepalive_seconds = _sse_keepalive_seconds()
    last_keepalive = time.monotonic()

    _record_stream_open(transport=transport, topics=topics, replay_after_cursor=replay_after_cursor)
    yield format_sse_chunk(comment="stream-open")

    drain_token = realtime_drain.register()
    drained = False
    try:
        async for batch in _iter_stream_batches(
            disconnect_check=lambda: _request_is_disconnected(request),
            principal=principal,
            redis_client=redis_client,
            topics=topics,
            replay_after_cursor=replay_after_cursor,
            transport=transport,
        ):
            if realtime_drain.is_draining():
                yield format_sse_chunk(data=REALTIME_DRAIN_SIGNAL_JSON)
                drained = True
                break
            admission.renew()
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
        _record_stream_close(transport=transport, reason="draining" if drained else "client_disconnect")
    finally:
        realtime_drain.deregister(drain_token)
        admission.release()


@router.get("/portal")
async def portal_stream_endpoint(
    request: Request,
    st: str = Query(..., min_length=1, max_length=4096, description="Short-lived stream token"),
    topics: str | None = Query(None, min_length=1, max_length=256, description="CSV of requested realtime topics"),
    cursor: str | None = Query(None, min_length=1, max_length=64, description="Last processed cursor for replay"),
):
    principal, resolved_topics, redis_client, admission = _resolve_stream_session(
        stream_token=st, topics=topics, transport="sse"
    )

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
            admission=admission,
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
        principal, resolved_topics, redis_client, admission = _resolve_stream_session(
            stream_token=stream_token, topics=topics, transport="ws"
        )
    except HTTPException as exc:
        close_code = status.WS_1008_POLICY_VIOLATION if exc.status_code in {401, 403} else 1013
        await websocket.close(code=close_code, reason=str(exc.detail))
        return

    _record_stream_open(transport="ws", topics=resolved_topics, replay_after_cursor=cursor_to_int(cursor))

    keepalive_seconds = _ws_keepalive_seconds()
    last_keepalive = time.monotonic()

    ping_active = _ws_ping_enabled() and callable(getattr(websocket, "receive_text", None))
    ping_interval = _ws_ping_interval_seconds()
    pong_timeout = _ws_pong_timeout_seconds()
    liveness = {"last_pong": time.monotonic(), "disconnected": False}
    last_ping_sent = 0.0
    pong_reader = asyncio.create_task(_ws_pong_reader(websocket, liveness)) if ping_active else None

    drain_token = realtime_drain.register()
    try:
        async for batch in _iter_stream_batches(
            disconnect_check=lambda: _websocket_is_disconnected(websocket),
            principal=principal,
            redis_client=redis_client,
            topics=resolved_topics,
            replay_after_cursor=cursor_to_int(cursor),
            transport="ws",
        ):
            if realtime_drain.is_draining():
                await websocket.close(code=1001, reason=REALTIME_DRAIN_CLOSE_REASON)
                _record_stream_close(transport="ws", reason="draining")
                return
            admission.renew()
            if batch:
                for envelope in batch:
                    await websocket.send_text(envelope.as_json())
                last_keepalive = time.monotonic()
                continue

            now = time.monotonic()
            if now - last_keepalive >= float(keepalive_seconds):
                last_keepalive = now
                await websocket.send_text('{"kind":"keepalive","transport":"ws"}')

            if ping_active:
                if liveness["disconnected"]:
                    _record_stream_close(transport="ws", reason="client_disconnect")
                    return
                if last_ping_sent <= 0.0 or (
                    now - last_ping_sent >= float(ping_interval) and liveness["last_pong"] >= last_ping_sent
                ):
                    last_ping_sent = now
                    await websocket.send_text(f'{{"kind":"ping","ts":{int(now * 1000)}}}')
                elif liveness["last_pong"] < last_ping_sent and now - last_ping_sent >= float(pong_timeout):
                    await websocket.close(
                        code=REALTIME_PING_TIMEOUT_CLOSE_CODE,
                        reason=REALTIME_PING_TIMEOUT_CLOSE_REASON,
                    )
                    _record_stream_close(transport="ws", reason="ping_timeout")
                    return
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
    finally:
        if pong_reader is not None:
            pong_reader.cancel()
            try:
                await pong_reader
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        realtime_drain.deregister(drain_token)
        admission.release()
