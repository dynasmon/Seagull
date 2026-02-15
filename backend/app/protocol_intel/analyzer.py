from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from .classify import guess_application_proto
from .dns import parse_dns_message
from .http import parse_http_request
from .tls import parse_tls_client_hello


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _first_present(extra: Dict[str, Any], keys: Tuple[str, ...]) -> Optional[Any]:
    for k in keys:
        if k in extra and extra[k] not in (None, ""):
            return extra[k]
    return None


def _decode_b64_maybe(value: Any, max_bytes: int) -> Optional[bytes]:
    """Decode base64 if value looks like base64; otherwise return None.

    The worker is expected to provide the raw bytes in base64 form.
    We cap bytes to prevent memory abuse.
    """

    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None

    # Fast-path: allow padding-less b64.
    try:
        raw = base64.b64decode(s + "==", validate=False)
    except (binascii.Error, ValueError):
        return None

    if not raw:
        return None
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    return raw


def extract_l7_bytes(extra: Dict[str, Any], max_bytes: int) -> Optional[bytes]:
    """Try multiple conventions for where the agent stores L7 bytes."""

    # Nested object convention: extra["l7"]["payload_b64"]
    l7 = extra.get("l7")
    if isinstance(l7, dict):
        v = _first_present(l7, ("payload_b64", "raw_b64", "data_b64"))
        b = _decode_b64_maybe(v, max_bytes)
        if b:
            return b

    # Flat keys.
    v = _first_present(
        extra,
        (
            "payload_b64",
            "l7_payload_b64",
            "raw_payload_b64",
            "dns_raw_b64",
            "http_raw_b64",
            "tls_client_hello_b64",
        ),
    )
    return _decode_b64_maybe(v, max_bytes)


def analyze_event(
    *,
    event_type: str,
    proto: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    extra: Dict[str, Any],
    payload_max_bytes: int = 4096,
) -> Dict[str, Any]:
    """Derive protocol metadata for a single event.

    Returns a patch dict to merge into net_events.extra.
    """

    patch: Dict[str, Any] = {}

    # Lightweight app proto guess (works even without payload).
    guess, confidence, reason = guess_application_proto(
        event_type=event_type,
        transport=proto,
        src_port=src_port,
        dst_port=dst_port,
        extra=extra,
    )
    if guess:
        patch["app_proto"] = guess
        patch["app_proto_confidence"] = confidence
        patch["app_proto_reason"] = reason

    payload = extract_l7_bytes(extra, payload_max_bytes)

    # Protocol-aware parsing (only when we have enough bytes).
    if payload:
        if guess == "dns" or (dst_port == 53 or src_port == 53):
            dns = parse_dns_message(payload)
            patch.update(dns)

        if guess == "http" or (dst_port in (80, 8080, 8000, 8888) or src_port in (80, 8080, 8000, 8888)):
            http = parse_http_request(payload)
            patch.update(http)

        # TLS over TCP, DTLS, and QUIC (QUIC requires external extraction; we only consume TLS ClientHello bytes).
        if guess in ("tls", "quic", "dtls") or (dst_port in (443, 8443) or src_port in (443, 8443)):
            tls = parse_tls_client_hello(payload, extra=extra)
            patch.update(tls)

    # Marker to make the worker idempotent.
    if patch:
        patch["proto_intel_at"] = _utc_now_iso()

    return patch
