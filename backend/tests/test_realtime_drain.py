from __future__ import annotations

import asyncio
import os
import signal
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from starlette.websockets import WebSocketState

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://u:p@localhost:5432/seagull")

from app import main
from app.core.config import settings
from app.core.realtime.drain import RealtimeDrainController, realtime_drain
from app.features.realtime import api as realtime_api
from app.features.realtime import service as realtime_service


@pytest.fixture(autouse=True)
def _reset_drain_state():
    realtime_drain.reset_state()
    yield
    realtime_drain.reset_state()


def _stream_token(*, user_id: int = 7, role: str = "admin") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "typ": realtime_service.STREAM_TOKEN_TYPE,
        "sub": str(user_id),
        "usr": "eve",
        "role": role,
        "purpose": realtime_service.STREAM_TOKEN_PURPOSE,
        "scope": realtime_service.STREAM_TOKEN_SCOPE,
        "scopes": [realtime_service.STREAM_TOKEN_SCOPE, realtime_service.STREAM_TOKEN_SCOPE_ADMIN],
        "iss": settings.SEAGULL_JWT_ISSUER,
        "aud": f"{settings.SEAGULL_JWT_AUDIENCE}{realtime_service.STREAM_TOKEN_AUDIENCE_SUFFIX}",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "drain-jti",
    }
    return jwt.encode(payload, settings.SEAGULL_JWT_SECRET, algorithm="HS256")


def _admin_principal() -> realtime_service.StreamPrincipal:
    return realtime_service.StreamPrincipal(
        user_id=7,
        username="eve",
        role="admin",
        scope=realtime_service.STREAM_TOKEN_SCOPE,
        scopes=(realtime_service.STREAM_TOKEN_SCOPE, realtime_service.STREAM_TOKEN_SCOPE_ADMIN),
        purpose=realtime_service.STREAM_TOKEN_PURPOSE,
    )


class _EmptyRedis:
    def xrevrange(self, *_args, **_kwargs):
        return []

    def xread(self, *_args, **_kwargs):
        return []


class _DrainOnReadRedis:
    def xrevrange(self, *_args, **_kwargs):
        return []

    def xread(self, *_args, **_kwargs):
        realtime_drain.begin_draining()
        return []


class _NeverDisconnectRequest:
    async def is_disconnected(self) -> bool:
        return False


def _no_op_admission() -> realtime_api.ConnectionAdmission:
    return realtime_api.ConnectionAdmission(admitted=True, reason="test", active_connections=0)


def test_drain_controller_register_and_count() -> None:
    controller = RealtimeDrainController()
    first = controller.register()
    second = controller.register()
    assert controller.active_connection_count() == 2
    controller.deregister(first)
    assert controller.active_connection_count() == 1
    controller.deregister(second)
    assert controller.active_connection_count() == 0


def test_drain_controller_begin_and_reset() -> None:
    controller = RealtimeDrainController()
    assert controller.is_draining() is False
    controller.begin_draining()
    assert controller.is_draining() is True
    controller.register()
    controller.reset_state()
    assert controller.is_draining() is False
    assert controller.active_connection_count() == 0


def test_chained_signal_handler_sets_draining_and_chains() -> None:
    controller = RealtimeDrainController()
    chained = {"called": False, "signum": None}

    def _previous(signum, _frame):
        chained["called"] = True
        chained["signum"] = signum

    handler = controller._chained_handler(_previous)
    handler(signal.SIGTERM, None)

    assert controller.is_draining() is True
    assert chained["called"] is True
    assert chained["signum"] == signal.SIGTERM


def test_install_signal_handlers_is_idempotent(monkeypatch) -> None:
    controller = RealtimeDrainController()
    installs: list[int] = []
    monkeypatch.setattr("app.core.realtime.drain.signal.getsignal", lambda sig: None)
    monkeypatch.setattr("app.core.realtime.drain.signal.signal", lambda sig, handler: installs.append(int(sig)))

    controller.install_signal_handlers()
    controller.install_signal_handlers()

    assert sorted(installs) == sorted([int(signal.SIGTERM), int(signal.SIGINT)])


def test_resolve_stream_session_rejects_new_connection_when_draining(monkeypatch) -> None:
    monkeypatch.setattr(realtime_api, "get_redis", lambda decode_responses=True: object())
    realtime_drain.begin_draining()

    try:
        realtime_api._resolve_stream_session(stream_token=_stream_token(), topics="overview", transport="sse")
    except HTTPException as exc:
        assert exc.status_code == 503
        assert exc.detail == realtime_api.REALTIME_DRAINING_DETAIL
    else:
        raise AssertionError("expected draining rejection for a new connection")


def test_sse_stream_emits_drain_frame_when_draining() -> None:
    realtime_drain.begin_draining()

    async def _run() -> list[str]:
        out: list[str] = []
        async for chunk in realtime_api._stream_events(
            _NeverDisconnectRequest(),
            principal=_admin_principal(),
            redis_client=_EmptyRedis(),
            topics=["overview"],
            replay_after_cursor=0,
            transport="sse",
            admission=_no_op_admission(),
        ):
            out.append(chunk)
            if len(out) >= 5:
                break
        return out

    chunks = asyncio.run(_run())
    full = "".join(chunks)
    assert '"kind":"drain"' in full
    assert realtime_drain.active_connection_count() == 0


def test_websocket_closes_1001_when_draining_mid_stream(monkeypatch) -> None:
    monkeypatch.setattr(realtime_api, "get_redis", lambda decode_responses=True: _DrainOnReadRedis())
    monkeypatch.setattr(realtime_api, "_ws_keepalive_seconds", lambda: 0)

    close_calls: list[tuple] = []

    class _MockWS:
        query_params: dict = {"st": _stream_token(), "topics": "overview", "cursor": "0"}
        application_state = WebSocketState.CONNECTED
        client_state = WebSocketState.CONNECTED

        async def accept(self) -> None:
            pass

        async def send_text(self, data: str) -> None:
            pass

        async def close(self, code: int | None = None, reason: str | None = None) -> None:
            close_calls.append((code, reason))

    asyncio.run(realtime_api.portal_websocket_endpoint(_MockWS()))  # type: ignore[arg-type]

    assert close_calls, "expected websocket.close() when draining mid-stream"
    code, reason = close_calls[0]
    assert code == 1001
    assert reason == realtime_api.REALTIME_DRAIN_CLOSE_REASON
    assert realtime_drain.active_connection_count() == 0


def test_shutdown_hook_returns_fast_when_no_active_connections(monkeypatch) -> None:
    monkeypatch.setattr(main, "_shutdown_drain_seconds", lambda: 5.0)
    start = time.monotonic()
    asyncio.run(main._shutdown())
    elapsed = time.monotonic() - start
    assert elapsed < 1.0


def test_shutdown_hook_is_bounded_when_connection_never_drains(monkeypatch) -> None:
    monkeypatch.setattr(main, "_shutdown_drain_seconds", lambda: 0.3)
    realtime_drain.register()
    start = time.monotonic()
    asyncio.run(main._shutdown())
    elapsed = time.monotonic() - start
    assert 0.3 <= elapsed < 1.5


def test_shutdown_hook_marks_draining_during_wait(monkeypatch) -> None:
    monkeypatch.setattr(main, "_shutdown_drain_seconds", lambda: 0.3)
    observed: dict[str, bool] = {}
    real_sleep = asyncio.sleep

    async def _recording_sleep(delay: float) -> None:
        observed.setdefault("draining", realtime_drain.is_draining())
        await real_sleep(delay)

    monkeypatch.setattr(main.asyncio, "sleep", _recording_sleep)
    realtime_drain.register()
    asyncio.run(main._shutdown())

    assert observed.get("draining") is True
    assert realtime_drain.is_draining() is False
