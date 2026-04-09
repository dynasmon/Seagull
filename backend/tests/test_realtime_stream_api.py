from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from jose import jwt

os.environ.setdefault("NETWATCH_SKIP_STARTUP_BOOTSTRAP", "true")
os.environ.setdefault("NETWATCH_JWT_SECRET", "x" * 40)

from app.core.config import settings
from app.core.portal_auth import PortalPrincipal, get_current_user
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


def test_sse_chunk_format_supports_named_event_and_multiline_data() -> None:
    chunk = realtime_service.format_sse_chunk(event="overview.updated", data='{"a":1}\n{"b":2}')
    assert chunk == "event: overview.updated\ndata: {\"a\":1}\ndata: {\"b\":2}\n\n"
