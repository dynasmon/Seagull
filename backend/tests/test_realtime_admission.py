from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketState

os.environ.setdefault("SEAGULL_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("SEAGULL_JWT_SECRET", "x" * 40)
os.environ.setdefault("SEAGULL_DB_URL", "postgresql://u:p@localhost:5432/seagull")

from app.core.config import settings
from app.core.realtime import admission
from app.core.security.rate_limit import RateLimitResult, limit_key
from app.features.auth.session import PortalPrincipal, get_current_user
from app.features.realtime import api as realtime_api
from app.features.realtime import service as realtime_service
from app.main import app


class _LedgerRedis:
    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}

    def eval(self, _script: str, _numkeys: int, *args):
        key = args[0]
        now = float(args[1])
        ttl = float(args[2])
        max_connections = int(args[3])
        member = args[4]
        bucket = self.zsets.setdefault(key, {})
        cutoff = now - ttl
        for stale in [m for m, score in list(bucket.items()) if score <= cutoff]:
            del bucket[stale]
        active = len(bucket)
        if active >= max_connections:
            return [0, active]
        bucket[member] = now
        return [1, active + 1]

    def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    def zrem(self, key: str, *members: str) -> None:
        bucket = self.zsets.get(key, {})
        for member in members:
            bucket.pop(member, None)

    def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    def expire(self, _key: str, _ttl: int) -> bool:
        return True

    def pipeline(self) -> "_LedgerPipe":
        return _LedgerPipe(self)


class _LedgerPipe:
    def __init__(self, backing: _LedgerRedis) -> None:
        self._backing = backing
        self._ops: list[tuple] = []

    def zadd(self, key: str, mapping: dict[str, float]) -> "_LedgerPipe":
        self._ops.append(("zadd", key, mapping))
        return self

    def expire(self, key: str, ttl: int) -> "_LedgerPipe":
        self._ops.append(("expire", key, ttl))
        return self

    def execute(self) -> list:
        for name, *rest in self._ops:
            getattr(self._backing, name)(*rest)
        self._ops = []
        return []


class _ExplodingRedis:
    def eval(self, *_args, **_kwargs):
        raise RuntimeError("ledger backend down")


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
        "jti": "admission-jti",
    }
    return jwt.encode(payload, settings.SEAGULL_JWT_SECRET, algorithm="HS256")


def _ledger(redis_client, *, max_connections: int = 2, ttl_seconds: int = 60) -> admission.PortalRealtimeConnectionLedger:
    return admission.PortalRealtimeConnectionLedger(
        redis_client,
        max_connections_per_user=max_connections,
        connection_ttl_seconds=ttl_seconds,
    )


def test_admission_allows_under_limit() -> None:
    ledger = _ledger(_LedgerRedis(), max_connections=3)
    first = ledger.admit(user_id=5)
    second = ledger.admit(user_id=5)
    third = ledger.admit(user_id=5)
    assert [first.admitted, second.admitted, third.admitted] == [True, True, True]
    assert [first.active_connections, second.active_connections, third.active_connections] == [1, 2, 3]


def test_admission_rejects_at_limit() -> None:
    ledger = _ledger(_LedgerRedis(), max_connections=2)
    assert ledger.admit(user_id=5).admitted
    assert ledger.admit(user_id=5).admitted
    rejected = ledger.admit(user_id=5)
    assert rejected.admitted is False
    assert rejected.reason == "concurrency_limit"
    assert rejected.active_connections == 2


def test_admission_is_isolated_per_user() -> None:
    backing = _LedgerRedis()
    ledger = _ledger(backing, max_connections=1)
    assert ledger.admit(user_id=1).admitted
    assert ledger.admit(user_id=1).admitted is False
    assert ledger.admit(user_id=2).admitted


def test_admission_release_frees_slot() -> None:
    ledger = _ledger(_LedgerRedis(), max_connections=1)
    held = ledger.admit(user_id=5)
    assert held.admitted
    assert ledger.admit(user_id=5).admitted is False
    held.release()
    assert ledger.admit(user_id=5).admitted


def test_admission_release_is_idempotent() -> None:
    ledger = _ledger(_LedgerRedis(), max_connections=1)
    held = ledger.admit(user_id=5)
    held.release()
    held.release()
    assert ledger.admit(user_id=5).admitted


def test_admission_self_heals_after_abrupt_disconnect(monkeypatch) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(admission.time, "time", lambda: clock["now"])
    ledger = _ledger(_LedgerRedis(), max_connections=2, ttl_seconds=60)

    assert ledger.admit(user_id=5).admitted
    assert ledger.admit(user_id=5).admitted
    assert ledger.admit(user_id=5).admitted is False

    clock["now"] += 61.0

    healed = ledger.admit(user_id=5)
    assert healed.admitted
    assert healed.active_connections == 1


def test_admission_coordinates_across_two_worker_processes() -> None:
    shared = _LedgerRedis()
    worker_a = _ledger(shared, max_connections=2)
    worker_b = _ledger(shared, max_connections=2)

    assert worker_a.admit(user_id=9).admitted
    assert worker_b.admit(user_id=9).admitted
    assert worker_a.admit(user_id=9).admitted is False
    assert worker_b.admit(user_id=9).admitted is False


def test_admission_fails_open_when_redis_missing() -> None:
    ledger = _ledger(None, max_connections=1)
    decision = ledger.admit(user_id=5)
    assert decision.admitted
    assert decision.reason == "ledger_unavailable"


def test_admission_fails_open_on_ledger_error() -> None:
    ledger = _ledger(_ExplodingRedis(), max_connections=1)
    decision = ledger.admit(user_id=5)
    assert decision.admitted
    assert decision.reason == "ledger_unavailable"
    decision.renew()
    decision.release()


def test_resolve_stream_session_rejects_at_connection_limit(monkeypatch) -> None:
    shared = _LedgerRedis()
    monkeypatch.setattr(realtime_api, "get_redis", lambda decode_responses=True: shared)
    monkeypatch.setattr(settings, "SEAGULL_REALTIME_MAX_CONNECTIONS_PER_USER", 1)

    token = _stream_token()
    principal, topics, _redis, admitted = realtime_api._resolve_stream_session(
        stream_token=token, topics="overview", transport="sse"
    )
    assert admitted.admitted
    assert principal.user_id == 7
    assert topics == ["overview"]

    try:
        realtime_api._resolve_stream_session(stream_token=token, topics="overview", transport="sse")
    except HTTPException as exc:
        assert exc.status_code == 503
        assert exc.detail == realtime_api.REALTIME_CONCURRENCY_LIMIT_DETAIL
    else:
        raise AssertionError("expected concurrency rejection at the connection limit")


def test_resolve_stream_session_release_returns_slot(monkeypatch) -> None:
    shared = _LedgerRedis()
    monkeypatch.setattr(realtime_api, "get_redis", lambda decode_responses=True: shared)
    monkeypatch.setattr(settings, "SEAGULL_REALTIME_MAX_CONNECTIONS_PER_USER", 1)

    token = _stream_token()
    _p, _t, _r, first = realtime_api._resolve_stream_session(stream_token=token, topics="overview", transport="sse")
    first.release()
    _p2, _t2, _r2, second = realtime_api._resolve_stream_session(stream_token=token, topics="overview", transport="sse")
    assert second.admitted


def test_websocket_closes_with_concurrency_reason_at_limit(monkeypatch) -> None:
    shared = _LedgerRedis()
    monkeypatch.setattr(realtime_api, "get_redis", lambda decode_responses=True: shared)
    monkeypatch.setattr(settings, "SEAGULL_REALTIME_MAX_CONNECTIONS_PER_USER", 1)

    pre_existing = _ledger(shared, max_connections=1)
    assert pre_existing.admit(user_id=7).admitted

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

    assert close_calls, "expected websocket.close() at the connection limit"
    code, reason = close_calls[0]
    assert code == 1013
    assert reason == realtime_api.REALTIME_CONCURRENCY_LIMIT_DETAIL


def test_token_endpoint_returns_429_when_rate_limited(monkeypatch) -> None:
    calls = {"n": 0}

    def _fake_rate_limit(
        scope: str, dimension: str, identity: str, *, limit: int, window_seconds: int
    ) -> RateLimitResult:
        calls["n"] += 1
        return RateLimitResult(allowed=calls["n"] <= 1, remaining=0, reset_seconds=window_seconds)

    monkeypatch.setattr(realtime_api, "rate_limit", _fake_rate_limit)
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=11, username="rl", role="user")
    try:
        with TestClient(app) as client:
            assert client.post("/realtime/token").status_code == 200
            assert client.post("/realtime/token").status_code == 429
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_token_endpoint_rate_limit_keyed_by_user_id(monkeypatch) -> None:
    seen: dict[str, str] = {}

    def _fake_rate_limit(
        scope: str, dimension: str, identity: str, *, limit: int, window_seconds: int
    ) -> RateLimitResult:
        seen["key"] = limit_key(scope, dimension, identity)
        return RateLimitResult(allowed=True, remaining=limit, reset_seconds=window_seconds)

    monkeypatch.setattr(realtime_api, "rate_limit", _fake_rate_limit)
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=77, username="rl", role="user")
    try:
        with TestClient(app) as client:
            assert client.post("/realtime/token").status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert seen["key"] == "rl:realtime-token:user:77"
