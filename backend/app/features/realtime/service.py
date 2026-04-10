from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional

from jose import jwt

from app.core.config import settings
from app.core.portal_auth import PortalPrincipal
from app.core.realtime import portal_realtime_topics, publish_portal_realtime_message
from app.features.realtime.schemas import RealtimeEnvelope


STREAM_TOKEN_TYPE = "stream_bootstrap"
STREAM_TOKEN_PURPOSE = "portal_realtime_stream"
STREAM_TOKEN_SCOPE = "portal:realtime"
STREAM_TOKEN_SCOPE_ADMIN = "portal:admin"
STREAM_TOKEN_AUDIENCE_SUFFIX = ":stream"

REALTIME_EVENT_POLICIES: dict[str, dict[str, str]] = {
    "overview.invalidate": {"topic": "overview", "mode": "invalidate", "scope": STREAM_TOKEN_SCOPE},
    "overview.patch": {"topic": "overview", "mode": "patch", "scope": STREAM_TOKEN_SCOPE},
    "storm.status": {"topic": "overview", "mode": "replace", "scope": STREAM_TOKEN_SCOPE},
    "agent.heartbeat": {"topic": "agents", "mode": "patch", "scope": STREAM_TOKEN_SCOPE},
    "alert.created": {"topic": "alerts", "mode": "append", "scope": STREAM_TOKEN_SCOPE_ADMIN},
    "alert.updated": {"topic": "alerts", "mode": "patch", "scope": STREAM_TOKEN_SCOPE_ADMIN},
}
DEFAULT_REALTIME_POLICY = {"topic": "overview", "mode": "append", "scope": STREAM_TOKEN_SCOPE}

TOPIC_REQUIRED_SCOPE: dict[str, str] = {
    "overview": STREAM_TOKEN_SCOPE,
    "agents": STREAM_TOKEN_SCOPE,
    "alerts": STREAM_TOKEN_SCOPE_ADMIN,
}


@dataclass(frozen=True)
class StreamPrincipal:
    user_id: int
    username: str
    role: str
    scope: str
    scopes: tuple[str, ...]
    purpose: str

    @property
    def is_admin(self) -> bool:
        return (self.role or "").lower() == "admin"

    def has_scope(self, scope: str) -> bool:
        wanted = str(scope or "").strip().lower()
        if not wanted:
            return False
        if wanted in {str(x or "").strip().lower() for x in self.scopes}:
            return True
        return str(self.scope or "").strip().lower() == wanted


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


def _normalize_scopes(values: Iterable[Any]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip().lower()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return tuple(out)


def realtime_event_policy(event_type: str) -> dict[str, str]:
    key = str(event_type or "").strip()
    if key in REALTIME_EVENT_POLICIES:
        return REALTIME_EVENT_POLICIES[key]
    return DEFAULT_REALTIME_POLICY


def _topic_for_event(event_type: str) -> str:
    return realtime_event_policy(event_type).get("topic", "overview")


def _mode_for_event(event_type: str) -> str:
    return realtime_event_policy(event_type).get("mode", "append")


def _scope_for_event(event_type: str) -> str:
    return realtime_event_policy(event_type).get("scope", STREAM_TOKEN_SCOPE)


def available_realtime_topics() -> tuple[str, ...]:
    return portal_realtime_topics()


def parse_requested_topics(raw_topics: str | None) -> list[str]:
    available = set(available_realtime_topics())
    raw = str(raw_topics or "").strip()
    if not raw:
        return list(available_realtime_topics())

    out: list[str] = []
    seen: set[str] = set()
    for chunk in raw.split(","):
        topic = str(chunk or "").strip().lower()
        if not topic or topic in seen or topic not in available:
            continue
        seen.add(topic)
        out.append(topic)
    return out


def resolve_stream_topics(*, principal: StreamPrincipal, requested_topics: list[str]) -> list[str]:
    allowed: list[str] = []
    for topic in requested_topics:
        required = TOPIC_REQUIRED_SCOPE.get(topic, STREAM_TOKEN_SCOPE)
        if principal.has_scope(required):
            allowed.append(topic)
    return allowed


def issue_stream_token(*, user: PortalPrincipal) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    ttl_seconds = _stream_ttl_seconds()

    scopes = [STREAM_TOKEN_SCOPE]
    if str(user.role or "").strip().lower() == "admin":
        scopes.append(STREAM_TOKEN_SCOPE_ADMIN)

    payload = {
        "typ": STREAM_TOKEN_TYPE,
        "sub": str(int(user.id)),
        "usr": str(user.username),
        "role": str(user.role),
        "purpose": STREAM_TOKEN_PURPOSE,
        "scope": STREAM_TOKEN_SCOPE,
        "scopes": _normalize_scopes(scopes),
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

    role = str(payload.get("role") or "")
    raw_scopes = payload.get("scopes")
    if isinstance(raw_scopes, list):
        scopes = _normalize_scopes(raw_scopes)
    else:
        scopes = _normalize_scopes([payload.get("scope")])

    if str(role or "").strip().lower() == "admin" and STREAM_TOKEN_SCOPE_ADMIN not in scopes:
        scopes = _normalize_scopes([*scopes, STREAM_TOKEN_SCOPE_ADMIN])

    return StreamPrincipal(
        user_id=int(sub, 10),
        username=str(payload.get("usr") or ""),
        role=role,
        scope=str(payload.get("scope") or ""),
        scopes=scopes,
        purpose=str(payload.get("purpose") or ""),
    )


def build_realtime_envelope(
    *,
    event_type: str,
    payload: Dict[str, Any],
    topic: str | None = None,
    scope: str | None = None,
    mode: str | None = None,
    cursor: str | None = None,
) -> RealtimeEnvelope:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    return RealtimeEnvelope(
        version=2,
        topic=str(topic or _topic_for_event(event_type)),
        type=str(event_type or "").strip(),
        cursor=str(cursor or "0"),
        timestamp=datetime.now(timezone.utc),
        scope=str(scope or _scope_for_event(event_type)),
        mode=str(mode or _mode_for_event(event_type)),
        payload=payload,
    )


def publish_realtime(
    event_type: str,
    payload: Dict[str, Any],
    *,
    topic: str | None = None,
    scope: str | None = None,
    mode: str | None = None,
) -> bool:
    envelope = build_realtime_envelope(event_type=event_type, payload=payload, topic=topic, scope=scope, mode=mode)
    return publish_portal_realtime_message(envelope.as_json(), topic=envelope.topic)


def _cursor_to_int(cursor: str | None) -> int:
    raw = str(cursor or "").strip()
    if not raw or not raw.isdigit():
        return 0
    try:
        out = int(raw, 10)
    except Exception:
        return 0
    if out < 0:
        return 0
    return out


def cursor_to_int(cursor: str | None) -> int:
    return _cursor_to_int(cursor)


def envelope_cursor_to_int(envelope: RealtimeEnvelope) -> int:
    return _cursor_to_int(envelope.cursor)


def _normalize_realtime_payload(parsed: Dict[str, Any]) -> Dict[str, Any]:
    event_type = str(parsed.get("type") or "").strip()
    if not event_type:
        return parsed

    normalized = dict(parsed)
    policy = realtime_event_policy(event_type)

    if not str(normalized.get("topic") or "").strip():
        normalized["topic"] = policy.get("topic", "overview")
    if not str(normalized.get("scope") or "").strip():
        normalized["scope"] = policy.get("scope", STREAM_TOKEN_SCOPE)
    if not str(normalized.get("mode") or "").strip():
        normalized["mode"] = policy.get("mode", "append")

    cursor = _cursor_to_int(str(normalized.get("cursor") or ""))
    normalized["cursor"] = str(cursor)

    if "version" not in normalized:
        normalized["version"] = 1

    return normalized


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
        normalized = _normalize_realtime_payload(parsed)
        return RealtimeEnvelope(**normalized)
    except Exception:
        return None


def allow_envelope_for_stream(
    *,
    envelope: RealtimeEnvelope,
    principal: StreamPrincipal,
    allowed_topics: set[str] | None = None,
) -> bool:
    if allowed_topics is not None and envelope.topic not in allowed_topics:
        return False

    required_scope = str(envelope.scope or "").strip().lower()
    if required_scope and not principal.has_scope(required_scope):
        return False

    # Defense in depth: admin stream is always required for alert topic.
    if envelope.topic == "alerts" and not principal.is_admin:
        return False
    return True


def format_sse_chunk(
    *,
    event: str | None = None,
    data: str | None = None,
    comment: str | None = None,
    sse_id: str | None = None,
) -> str:
    lines: list[str] = []
    if comment is not None:
        lines.append(f": {str(comment)}")
    if sse_id is not None:
        lines.append(f"id: {str(sse_id)}")
    if event:
        lines.append(f"event: {str(event)}")
    if data is not None:
        chunks = str(data).splitlines() or [""]
        for chunk in chunks:
            lines.append(f"data: {chunk}")
    return "\n".join(lines) + "\n\n"
