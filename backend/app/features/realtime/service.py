from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from jose import jwt

from app.core.config import settings
from app.core.portal_auth import PortalPrincipal
from app.core.realtime import publish_portal_realtime_message
from app.features.realtime.schemas import RealtimeEnvelope


STREAM_TOKEN_TYPE = "stream_bootstrap"
STREAM_TOKEN_PURPOSE = "portal_realtime_stream"
STREAM_TOKEN_SCOPE = "portal:realtime"
STREAM_TOKEN_AUDIENCE_SUFFIX = ":stream"


@dataclass(frozen=True)
class StreamPrincipal:
    user_id: int
    username: str
    role: str
    scope: str
    purpose: str

    @property
    def is_admin(self) -> bool:
        return (self.role or "").lower() == "admin"


def _stream_ttl_seconds() -> int:
    configured = int(getattr(settings, "NETWATCH_REALTIME_STREAM_TOKEN_TTL_SECONDS", 30) or 30)
    if configured < 5:
        return 5
    if configured > 300:
        return 300
    return configured


def _stream_jwt_audience() -> str:
    return f"{settings.NETWATCH_JWT_AUDIENCE}{STREAM_TOKEN_AUDIENCE_SUFFIX}"


def _stream_jwt_secret() -> str:
    secret = (settings.NETWATCH_JWT_SECRET or "").strip()
    if not secret or len(secret) < 32:
        raise RuntimeError("NETWATCH_JWT_SECRET is missing/too short")
    return secret


def issue_stream_token(*, user: PortalPrincipal) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    ttl_seconds = _stream_ttl_seconds()

    payload = {
        "typ": STREAM_TOKEN_TYPE,
        "sub": str(int(user.id)),
        "usr": str(user.username),
        "role": str(user.role),
        "purpose": STREAM_TOKEN_PURPOSE,
        "scope": STREAM_TOKEN_SCOPE,
        "iss": settings.NETWATCH_JWT_ISSUER,
        "aud": _stream_jwt_audience(),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, _stream_jwt_secret(), algorithm="HS256")
    return token, ttl_seconds


def decode_stream_token(stream_token: str) -> StreamPrincipal:
    raw = str(stream_token or "").strip()
    if not raw:
        raise ValueError("missing stream token")

    try:
        payload: Dict[str, Any] = jwt.decode(
            raw,
            _stream_jwt_secret(),
            algorithms=["HS256"],
            audience=_stream_jwt_audience(),
            issuer=settings.NETWATCH_JWT_ISSUER,
            options={"require_iat": True, "require_exp": True, "require_sub": True, "require_jti": True},
        )
    except Exception as exc:
        raise ValueError("invalid stream token") from exc

    if str(payload.get("typ") or "") != STREAM_TOKEN_TYPE:
        raise ValueError("invalid stream token")
    if str(payload.get("purpose") or "") != STREAM_TOKEN_PURPOSE:
        raise ValueError("invalid stream token")
    if str(payload.get("scope") or "") != STREAM_TOKEN_SCOPE:
        raise ValueError("invalid stream token")

    sub = str(payload.get("sub") or "").strip()
    if not sub.isdigit():
        raise ValueError("invalid stream token")

    return StreamPrincipal(
        user_id=int(sub, 10),
        username=str(payload.get("usr") or ""),
        role=str(payload.get("role") or ""),
        scope=str(payload.get("scope") or ""),
        purpose=str(payload.get("purpose") or ""),
    )


def build_realtime_envelope(*, event_type: str, payload: Dict[str, Any]) -> RealtimeEnvelope:
    return RealtimeEnvelope(type=event_type, payload=payload)


def publish_realtime(event_type: str, payload: Dict[str, Any]) -> bool:
    envelope = build_realtime_envelope(event_type=event_type, payload=payload)
    return publish_portal_realtime_message(envelope.as_json())


def parse_realtime_envelope(raw_message: str) -> Optional[RealtimeEnvelope]:
    raw = str(raw_message or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    try:
        return RealtimeEnvelope(**parsed)
    except Exception:
        return None


def allow_envelope_for_stream(*, envelope: RealtimeEnvelope, principal: StreamPrincipal) -> bool:
    # Role-aware filtering hook for future authorization rules.
    _ = (envelope, principal)
    return True


def format_sse_chunk(*, event: str | None = None, data: str | None = None, comment: str | None = None) -> str:
    lines: list[str] = []
    if comment is not None:
        lines.append(f": {str(comment)}")
    if event:
        lines.append(f"event: {str(event)}")
    if data is not None:
        chunks = str(data).splitlines() or [""]
        for chunk in chunks:
            lines.append(f"data: {chunk}")
    return "\n".join(lines) + "\n\n"
