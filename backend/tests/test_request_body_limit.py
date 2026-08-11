from __future__ import annotations

import os

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)

import asyncio
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.core.api.body_limit import (
    INGEST_EVENTS_PATH,
    PAYLOAD_TOO_LARGE_DETAIL,
    BodyLimit,
    BodyLimitPolicy,
    RequestBodyLimitMiddleware,
    policy_from_settings,
)

_POLICY = BodyLimitPolicy(
    default=BodyLimit(name="default", max_bytes=64),
    routes=((INGEST_EVENTS_PATH, BodyLimit(name="ingest_events", max_bytes=256)),),
)


async def _echo_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
    read = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        read += len(message.get("body") or b"")
        if not message.get("more_body"):
            break
    body = json.dumps({"read": read}).encode("utf-8")
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


def _post(
    *,
    path: str,
    chunks: Iterable[bytes],
    declared_length: Optional[int],
    app: Any = _echo_app,
) -> Tuple[int, Dict[str, Any]]:
    headers: List[Tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    if declared_length is not None:
        headers.append((b"content-length", str(declared_length).encode("latin-1")))

    pending = list(chunks)
    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        if not pending:
            return {"type": "http.request", "body": b"", "more_body": False}
        chunk = pending.pop(0)
        return {"type": "http.request", "body": chunk, "more_body": bool(pending)}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    middleware = RequestBodyLimitMiddleware(app, policy=_POLICY)
    scope = {"type": "http", "method": "POST", "path": path, "headers": headers}
    asyncio.run(middleware(scope, receive, send))

    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(message.get("body") or b"" for message in sent if message["type"] == "http.response.body")
    return int(start["status"]), json.loads(body or b"{}")


def test_a_body_within_the_limit_reaches_the_route() -> None:
    status, payload = _post(path="/auth/login", chunks=[b"a" * 32], declared_length=32)

    assert status == 200
    assert payload["read"] == 32


def test_an_oversized_declared_length_is_rejected_before_the_body_is_read() -> None:
    reached: List[int] = []

    async def _counting_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
        reached.append(1)
        await _echo_app(scope, receive, send)

    status, payload = _post(
        path="/auth/login",
        chunks=[b"a" * 4096],
        declared_length=4096,
        app=_counting_app,
    )

    assert status == 413
    assert payload["detail"] == PAYLOAD_TOO_LARGE_DETAIL
    assert reached == []


def test_a_chunked_body_is_rejected_on_the_bytes_actually_received() -> None:
    status, payload = _post(
        path="/auth/login",
        chunks=[b"a" * 40, b"b" * 40, b"c" * 40],
        declared_length=None,
    )

    assert status == 413
    assert payload["detail"] == PAYLOAD_TOO_LARGE_DETAIL


def test_a_lying_content_length_does_not_buy_extra_bytes() -> None:
    status, _ = _post(path="/auth/login", chunks=[b"a" * 4096], declared_length=8)

    assert status == 413


def test_ingest_keeps_its_own_wider_limit() -> None:
    status, payload = _post(path=INGEST_EVENTS_PATH, chunks=[b"a" * 200], declared_length=200)
    assert status == 200
    assert payload["read"] == 200

    status, payload = _post(path=INGEST_EVENTS_PATH, chunks=[b"a" * 300], declared_length=None)
    assert status == 413
    assert payload["detail"] == PAYLOAD_TOO_LARGE_DETAIL


def test_non_http_scopes_are_passed_through_untouched() -> None:
    seen: List[str] = []

    async def _websocket_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
        seen.append(scope["type"])

    middleware = RequestBodyLimitMiddleware(_websocket_app, policy=_POLICY)
    asyncio.run(middleware({"type": "websocket", "path": "/realtime"}, None, None))

    assert seen == ["websocket"]


def test_settings_never_give_ingest_a_smaller_ceiling_than_the_default() -> None:
    policy = policy_from_settings()

    assert policy.limit_for("/auth/login").name == "default"
    assert policy.limit_for(INGEST_EVENTS_PATH).name == "ingest_events"
    assert policy.limit_for(INGEST_EVENTS_PATH).max_bytes >= policy.default.max_bytes
