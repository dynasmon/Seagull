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


class _FakeRedis:
    def __init__(self, *, replay_rows: list[tuple[str, dict[str, str]]], live_batches: list[list[tuple[str, dict[str, str]]]]):
        self._replay_rows = list(replay_rows)
        self._live_batches = [list(batch) for batch in live_batches]

    def xrevrange(self, _key: str, max: str, min: str, count: int):
        _ = (min, max)
        rows = list(self._replay_rows[-max(1, int(count)) :])
        rows.reverse()
        return rows

    def xread(self, streams: dict[str, str], count: int, block: int):
        _ = (count, block)
        stream_key = next(iter(streams.keys()))
        if not self._live_batches:
            return []
        batch = self._live_batches.pop(0)
        if not batch:
            return []
        return [(stream_key, batch)]


class _DisconnectAfter:
    def __init__(self, max_checks: int):
        self._checks = 0
        self._max_checks = int(max_checks)

    async def is_disconnected(self) -> bool:
        self._checks += 1
        return self._checks > self._max_checks


def _make_stream_row(*, stream_id: str, cursor: int, envelope_json: str) -> tuple[str, dict[str, str]]:
    return (
        stream_id,
        {
            "cursor": str(cursor),
            "topic": "overview",
            "envelope": envelope_json,
        },
    )


def _collect_stream_chunks(
    *,
    replay_rows: list[tuple[str, dict[str, str]]],
    live_batches: list[list[tuple[str, dict[str, str]]]],
    principal: realtime_service.StreamPrincipal,
    topics: list[str],
    replay_after_cursor: int,
    max_disconnect_checks: int = 3,
    max_chunks: int = 8,
) -> list[str]:
    redis_client = _FakeRedis(replay_rows=replay_rows, live_batches=live_batches)
    req = _DisconnectAfter(max_disconnect_checks)

    async def _run() -> list[str]:
        out: list[str] = []
        async for chunk in realtime_api._stream_events(
            req,
            principal=principal,
            redis_client=redis_client,
            topics=topics,
            replay_after_cursor=replay_after_cursor,
        ):
            out.append(chunk)
            if len(out) >= max_chunks:
                break
        return out

    return asyncio.run(_run())


def _admin_principal() -> realtime_service.StreamPrincipal:
    return realtime_service.StreamPrincipal(
        user_id=7,
        username="eve",
        role="admin",
        scope=realtime_service.STREAM_TOKEN_SCOPE,
        scopes=(realtime_service.STREAM_TOKEN_SCOPE, realtime_service.STREAM_TOKEN_SCOPE_ADMIN),
        purpose=realtime_service.STREAM_TOKEN_PURPOSE,
    )


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


def test_stream_events_emits_named_event_from_stream() -> None:
    chunks = _collect_stream_chunks(
        replay_rows=[],
        live_batches=[
            [
                _make_stream_row(
                    stream_id="1700000000000-0",
                    cursor=4,
                    envelope_json=(
                        '{"version":2,"topic":"overview","type":"overview.patch","cursor":"4",'
                        '"timestamp":"2026-04-09T12:00:00Z","scope":"portal:realtime","mode":"patch",'
                        '"payload":{"events_5m_delta":2}}'
                    ),
                )
            ]
        ],
        principal=_admin_principal(),
        topics=["overview", "alerts"],
        replay_after_cursor=0,
        max_disconnect_checks=4,
    )

    full = "".join(chunks)
    assert "event: overview.patch" in full
    assert "events_5m_delta" in full


def test_stream_events_replays_from_cursor_when_available() -> None:
    chunks = _collect_stream_chunks(
        replay_rows=[
            _make_stream_row(
                stream_id="1700000000000-0",
                cursor=3,
                envelope_json=(
                    '{"version":2,"topic":"overview","type":"overview.patch","cursor":"3",'
                    '"timestamp":"2026-04-09T12:00:00Z","scope":"portal:realtime","mode":"patch","payload":{}}'
                ),
            ),
            _make_stream_row(
                stream_id="1700000000001-0",
                cursor=4,
                envelope_json=(
                    '{"version":2,"topic":"overview","type":"overview.patch","cursor":"4",'
                    '"timestamp":"2026-04-09T12:00:01Z","scope":"portal:realtime","mode":"patch",'
                    '"payload":{"events_5m_delta":2}}'
                ),
            ),
        ],
        live_batches=[],
        principal=_admin_principal(),
        topics=["overview"],
        replay_after_cursor=3,
        max_disconnect_checks=2,
        max_chunks=3,
    )

    full = "".join(chunks)
    assert "event: overview.patch" in full
    assert '"cursor":"4"' in full
    assert '"cursor":"3"' not in full


def test_stream_events_emits_invalidate_on_cursor_gap() -> None:
    chunks = _collect_stream_chunks(
        replay_rows=[
            _make_stream_row(
                stream_id="1700000000100-0",
                cursor=100,
                envelope_json=(
                    '{"version":2,"topic":"overview","type":"overview.patch","cursor":"100",'
                    '"timestamp":"2026-04-09T12:00:00Z","scope":"portal:realtime","mode":"patch","payload":{}}'
                ),
            ),
            _make_stream_row(
                stream_id="1700000000101-0",
                cursor=101,
                envelope_json=(
                    '{"version":2,"topic":"agents","type":"agent.heartbeat","cursor":"101",'
                    '"timestamp":"2026-04-09T12:00:01Z","scope":"portal:realtime","mode":"patch","payload":{}}'
                ),
            ),
        ],
        live_batches=[],
        principal=_admin_principal(),
        topics=["overview", "agents"],
        replay_after_cursor=10,
        max_disconnect_checks=2,
        max_chunks=4,
    )

    full = "".join(chunks)
    assert "event: ui.overview.invalidate" in full
    assert "event: ui.agents.invalidate" in full
    assert "cursor_gap" in full


def test_stream_events_drops_malformed_payload_without_raw_echo() -> None:
    chunks = _collect_stream_chunks(
        replay_rows=[],
        live_batches=[[_make_stream_row(stream_id="1700000000200-0", cursor=12, envelope_json="not-json")]],
        principal=_admin_principal(),
        topics=["overview", "alerts"],
        replay_after_cursor=0,
        max_disconnect_checks=4,
    )
    full = "".join(chunks)
    assert "event: message" not in full
    assert "not-json" not in full


def test_stream_events_filters_admin_topic_for_non_admin() -> None:
    principal = realtime_service.StreamPrincipal(
        user_id=9,
        username="user",
        role="user",
        scope=realtime_service.STREAM_TOKEN_SCOPE,
        scopes=(realtime_service.STREAM_TOKEN_SCOPE,),
        purpose=realtime_service.STREAM_TOKEN_PURPOSE,
    )

    chunks = _collect_stream_chunks(
        replay_rows=[],
        live_batches=[
            [
                _make_stream_row(
                    stream_id="1700000000300-0",
                    cursor=12,
                    envelope_json=(
                        '{"version":2,"topic":"alerts","type":"alert.created","cursor":"12",'
                        '"timestamp":"2026-04-09T12:00:00Z","scope":"portal:admin","mode":"append",'
                        '"payload":{"alert_id":42}}'
                    ),
                )
            ]
        ],
        principal=principal,
        topics=["alerts"],
        replay_after_cursor=0,
        max_disconnect_checks=4,
    )

    full = "".join(chunks)
    assert "alert.created" not in full
