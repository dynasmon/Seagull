from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, Tuple

from starlette import status
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.core.observability import incr_counter, request_id

INGEST_EVENTS_PATH = "/ingest/events"
PAYLOAD_TOO_LARGE_DETAIL = "request payload too large"


@dataclass(frozen=True)
class BodyLimit:
    name: str
    max_bytes: int


@dataclass(frozen=True)
class BodyLimitPolicy:
    default: BodyLimit
    routes: Tuple[Tuple[str, BodyLimit], ...] = ()

    def limit_for(self, path: str) -> BodyLimit:
        for prefix, limit in self.routes:
            if path == prefix or path.startswith(f"{prefix}/"):
                return limit
        return self.default


class RequestBodyTooLarge(HTTPException):
    def __init__(self, limit: BodyLimit) -> None:
        super().__init__(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=PAYLOAD_TOO_LARGE_DETAIL,
        )
        self.limit = limit


def policy_from_settings() -> BodyLimitPolicy:
    default_max_bytes = max(1024, int(settings.SEAGULL_MAX_REQUEST_BODY_BYTES or 0))
    ingest_max_bytes = max(default_max_bytes, int(settings.SEAGULL_INGEST_MAX_REQUEST_BODY_BYTES or 0))
    return BodyLimitPolicy(
        default=BodyLimit(name="default", max_bytes=default_max_bytes),
        routes=((INGEST_EVENTS_PATH, BodyLimit(name="ingest_events", max_bytes=ingest_max_bytes)),),
    )


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, policy: BodyLimitPolicy) -> None:
        self.app = app
        self.policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        limit = self.policy.limit_for(str(scope.get("path") or ""))
        declared_bytes = _declared_body_bytes(scope)
        if declared_bytes is not None and declared_bytes > limit.max_bytes:
            await _reject(send, _rejected(limit))
            return

        response_started = False

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, _MeteredReceive(receive, limit), tracked_send)
        except RequestBodyTooLarge as exc:
            if response_started:
                raise
            await _reject(send, exc)


class _MeteredReceive:
    __slots__ = ("_limit", "_read_bytes", "_receive")

    def __init__(self, receive: Receive, limit: BodyLimit) -> None:
        self._receive = receive
        self._limit = limit
        self._read_bytes = 0

    async def __call__(self) -> Message:
        message = await self._receive()
        if message.get("type") == "http.request":
            self._read_bytes += len(message.get("body") or b"")
            if self._read_bytes > self._limit.max_bytes:
                raise _rejected(self._limit)
        return message


def _declared_body_bytes(scope: Scope) -> Optional[int]:
    for name, value in scope.get("headers") or ():
        if name != b"content-length":
            continue
        try:
            return int(value.decode("latin-1").strip())
        except ValueError:
            return None
    return None


def _rejected(limit: BodyLimit) -> RequestBodyTooLarge:
    incr_counter("http_request_body_rejected_total", policy=limit.name)
    return RequestBodyTooLarge(limit)


async def _reject(send: Send, exc: RequestBodyTooLarge) -> None:
    body = json.dumps(
        {"detail": exc.detail, "request_id": request_id() or ""},
        separators=(",", ":"),
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": exc.status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("latin-1")),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
