from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from jose import jwt

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core.config import settings
from app.core.portal_auth import PortalPrincipal, get_current_user
from app.features.realtime import api as realtime_api
from app.features.realtime import service as realtime_service
from app.main import app


def _expired_stream_token() -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "typ": realtime_service.STREAM_TOKEN_TYPE,
        "sub": "7",
        "usr": "eve",
        "role": "admin",
        "purpose": realtime_service.STREAM_TOKEN_PURPOSE,
        "scope": realtime_service.STREAM_TOKEN_SCOPE,
        "iss": settings.NETWATCH_JWT_ISSUER,
        "aud": f"{settings.NETWATCH_JWT_AUDIENCE}{realtime_service.STREAM_TOKEN_AUDIENCE_SUFFIX}",
        "iat": int((now - timedelta(minutes=2)).timestamp()),
        "exp": int((now - timedelta(minutes=1)).timestamp()),
        "jti": "expired-jti",
    }
    return jwt.encode(payload, settings.NETWATCH_JWT_SECRET, algorithm="HS256")


def _stream_token_with_claims(*, typ: str | None = None, purpose: str | None = None, scope: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "typ": typ if typ is not None else realtime_service.STREAM_TOKEN_TYPE,
        "sub": "7",
        "usr": "eve",
        "role": "admin",
        "purpose": purpose if purpose is not None else realtime_service.STREAM_TOKEN_PURPOSE,
        "scope": scope if scope is not None else realtime_service.STREAM_TOKEN_SCOPE,
        "iss": settings.NETWATCH_JWT_ISSUER,
        "aud": f"{settings.NETWATCH_JWT_AUDIENCE}{realtime_service.STREAM_TOKEN_AUDIENCE_SUFFIX}",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "claims-jti",
    }
    return jwt.encode(payload, settings.NETWATCH_JWT_SECRET, algorithm="HS256")


class _FakePubSub:
    def __init__(self, messages: list[dict]):
        self._messages = list(messages)
        self.subscribed: list[str] = []
        self.unsubscribed: list[str] = []
        self.closed = False

    def subscribe(self, *channels: str) -> None:
        self.subscribed.extend(list(channels))

    def unsubscribe(self, *channels: str) -> None:
        self.unsubscribed.extend(list(channels))

    def close(self) -> None:
        self.closed = True

    def get_message(self, _ignore_subscribe_messages: bool, _timeout: float):
        if self._messages:
            return self._messages.pop(0)
        return None


class _FakeRedis:
    def __init__(self, pubsub: _FakePubSub):
        self._pubsub = pubsub
        self._replay: dict[str, list[str]] = {}

    def pubsub(self, ignore_subscribe_messages: bool = True):
        _ = ignore_subscribe_messages
        return self._pubsub

    def lrange(self, key: str, _start: int, _end: int):
        return list(self._replay.get(key, []))


class _DisconnectAfter:
    def __init__(self, max_checks: int):
        self._checks = 0
        self._max_checks = int(max_checks)

    async def is_disconnected(self) -> bool:
        self._checks += 1
        return self._checks > self._max_checks


def _collect_stream_chunks(*, messages: list[dict], max_disconnect_checks: int = 3) -> tuple[list[str], _FakePubSub]:
    pubsub = _FakePubSub(messages)
    redis_client = _FakeRedis(pubsub)
    req = _DisconnectAfter(max_disconnect_checks)
    principal = realtime_service.StreamPrincipal(
        user_id=7,
        username="eve",
        role="admin",
        scope=realtime_service.STREAM_TOKEN_SCOPE,
        scopes=(realtime_service.STREAM_TOKEN_SCOPE, realtime_service.STREAM_TOKEN_SCOPE_ADMIN),
        purpose=realtime_service.STREAM_TOKEN_PURPOSE,
    )

    async def _run() -> list[str]:
        out: list[str] = []
        async for chunk in realtime_api._stream_events(
            req,
            principal=principal,
            redis_client=redis_client,
            topics=["overview", "alerts"],
            replay_after_cursor=0,
        ):
            out.append(chunk)
            if len(out) >= 6:
                break
        return out

    return asyncio.run(_run()), pubsub


def test_stream_token_issuance_for_authenticated_user() -> None:
    app.dependency_overrides[get_current_user] = lambda: PortalPrincipal(id=7, username="eve", role="admin")
    try:
        with TestClient(app) as client:
            r = client.post("/realtime/token")
            assert r.status_code == 200
            body = r.json()
            assert body["token_type"] == "stream"
            assert int(body["expires_in"]) > 0
            claims = jwt.get_unverified_claims(body["stream_token"])
            assert claims["typ"] == realtime_service.STREAM_TOKEN_TYPE
            assert claims["purpose"] == realtime_service.STREAM_TOKEN_PURPOSE
            assert claims["scope"] == realtime_service.STREAM_TOKEN_SCOPE
            assert realtime_service.STREAM_TOKEN_SCOPE in claims["scopes"]
            assert realtime_service.STREAM_TOKEN_SCOPE_ADMIN in claims["scopes"]
            assert claims["typ"] != "access"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_stream_token_issuance_rejects_without_auth() -> None:
    with TestClient(app) as client:
        r = client.post("/realtime/token")
        assert r.status_code == 401


def test_sse_endpoint_rejects_invalid_stream_token() -> None:
    with TestClient(app) as client:
        r = client.get("/realtime/portal?st=invalid-token")
        assert r.status_code == 401


def test_sse_endpoint_rejects_expired_stream_token() -> None:
    with TestClient(app) as client:
        r = client.get(f"/realtime/portal?st={_expired_stream_token()}")
        assert r.status_code == 401


def test_sse_endpoint_rejects_wrong_scope_claim() -> None:
    bad_scope = _stream_token_with_claims(scope="portal:admin")
    with TestClient(app) as client:
        r = client.get(f"/realtime/portal?st={bad_scope}")
        assert r.status_code == 401


def test_sse_endpoint_rejects_wrong_type_claim() -> None:
    bad_type = _stream_token_with_claims(typ="access")
    with TestClient(app) as client:
        r = client.get(f"/realtime/portal?st={bad_type}")
        assert r.status_code == 401


def test_sse_endpoint_rejects_wrong_purpose_claim() -> None:
    bad_purpose = _stream_token_with_claims(purpose="portal_access")
    with TestClient(app) as client:
        r = client.get(f"/realtime/portal?st={bad_purpose}")
        assert r.status_code == 401


def test_sse_chunk_format_supports_named_event_and_multiline_data() -> None:
    chunk = realtime_service.format_sse_chunk(event="overview.patch", sse_id="9", data='{"a":1}\n{"b":2}')
    assert chunk == "id: 9\nevent: overview.patch\ndata: {\"a\":1}\ndata: {\"b\":2}\n\n"


def test_stream_events_emits_named_event_and_cleans_up_pubsub() -> None:
    chunks, pubsub = _collect_stream_chunks(
        messages=[
            {
                "type": "message",
                "data": (
                    '{"version":2,"topic":"overview","type":"overview.patch","cursor":"4",'
                    '"timestamp":"2026-04-09T12:00:00Z","scope":"portal:realtime","mode":"patch",'
                    '"payload":{"events_5m_delta":2}}'
                ),
            }
        ],
        max_disconnect_checks=4,
    )

    full = "".join(chunks)
    assert "event: overview.patch" in full
    assert "events_5m_delta" in full
    assert pubsub.subscribed
    assert pubsub.unsubscribed
    assert pubsub.closed is True


def test_stream_events_drops_malformed_payload_without_raw_echo() -> None:
    chunks, _ = _collect_stream_chunks(
        messages=[{"type": "message", "data": "not-json"}],
        max_disconnect_checks=4,
    )
    full = "".join(chunks)
    assert "event: message" not in full
    assert "not-json" not in full


def test_stream_events_filters_admin_topic_for_non_admin() -> None:
    pubsub = _FakePubSub(
        [
            {
                "type": "message",
                "data": (
                    '{"version":2,"topic":"alerts","type":"alert.created","cursor":"12",'
                    '"timestamp":"2026-04-09T12:00:00Z","scope":"portal:admin","mode":"append",'
                    '"payload":{"alert_id":42}}'
                ),
            }
        ]
    )
    redis_client = _FakeRedis(pubsub)
    req = _DisconnectAfter(4)
    principal = realtime_service.StreamPrincipal(
        user_id=9,
        username="user",
        role="user",
        scope=realtime_service.STREAM_TOKEN_SCOPE,
        scopes=(realtime_service.STREAM_TOKEN_SCOPE,),
        purpose=realtime_service.STREAM_TOKEN_PURPOSE,
    )

    async def _run() -> list[str]:
        out: list[str] = []
        async for chunk in realtime_api._stream_events(
            req,
            principal=principal,
            redis_client=redis_client,
            topics=["alerts"],
            replay_after_cursor=0,
        ):
            out.append(chunk)
            if len(out) >= 4:
                break
        return out

    chunks = asyncio.run(_run())
    full = "".join(chunks)
    assert "alert.created" not in full
