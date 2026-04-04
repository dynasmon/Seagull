from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from .classify import confidence_band, guess_application_proto
from .dns import parse_dns_message
from .http import parse_http_message
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


def _extract_agent_l7(extra: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    l7 = extra.get("l7")
    if isinstance(l7, dict):
        out["protocol"] = str(l7.get("protocol") or "").strip().lower()
        if isinstance(l7.get("dns"), dict):
            out["dns"] = dict(l7.get("dns") or {})
        if isinstance(l7.get("http"), dict):
            out["http"] = dict(l7.get("http") or {})
        if isinstance(l7.get("tls"), dict):
            out["tls"] = dict(l7.get("tls") or {})

    # Flat compatibility keys.
    if isinstance(extra.get("dns_evidence"), dict) and "dns" not in out:
        out["dns"] = dict(extra.get("dns_evidence") or {})
    if isinstance(extra.get("http_evidence"), dict) and "http" not in out:
        out["http"] = dict(extra.get("http_evidence") or {})
    if "protocol" not in out or not out.get("protocol"):
        p = str(extra.get("l7_protocol") or "").strip().lower()
        if p:
            out["protocol"] = p
    if bool(extra.get("is_quic")):
        out["protocol"] = "quic"
    if bool(extra.get("is_dtls")):
        out["protocol"] = "dtls"
    return out


def _coerce_int(v: Any) -> Optional[int]:
    try:
        if v is None or v == "":
            return None
        return int(v)
    except Exception:
        return None


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

    agent_l7 = _extract_agent_l7(extra)

    # Agent evidence has priority over any fallback.
    agent_proto = str(agent_l7.get("protocol") or "").strip().lower()
    if agent_proto:
        patch["app_proto"] = agent_proto
        patch["app_proto_confidence"] = 99
        patch["app_proto_conf_band"] = confidence_band(99)
        patch["app_proto_reason"] = "agent_evidence"

    dns_ev = agent_l7.get("dns") if isinstance(agent_l7.get("dns"), dict) else {}
    if dns_ev:
        qname = str(dns_ev.get("qname") or "").strip().lower()
        if qname:
            patch["dns_qname"] = qname
        qtype = _coerce_int(dns_ev.get("qtype"))
        if qtype is not None:
            patch["dns_qtype"] = qtype
        rcode = _coerce_int(dns_ev.get("rcode"))
        if rcode is not None:
            patch["dns_rcode"] = rcode
        answers = dns_ev.get("answers")
        if isinstance(answers, list) and answers:
            patch["dns_answers"] = [str(a)[:256] for a in answers[:8]]

    http_ev = agent_l7.get("http") if isinstance(agent_l7.get("http"), dict) else {}
    if http_ev:
        method = str(http_ev.get("method") or "").strip().upper()
        host = str(http_ev.get("host") or "").strip().lower()
        path = str(http_ev.get("path") or "").strip()
        ua = str(http_ev.get("user_agent") or "").strip()
        status = str(http_ev.get("status") or "").strip()
        direction = str(http_ev.get("direction") or "").strip().lower()
        if method:
            patch["http_method"] = method
        if host:
            patch["http_host"] = host
        if path:
            patch["http_path"] = path
        if ua:
            patch["http_user_agent"] = ua
        if status:
            patch["http_status"] = status
        if direction:
            patch["http_direction"] = direction

    tls_ev = agent_l7.get("tls") if isinstance(agent_l7.get("tls"), dict) else {}
    if tls_ev:
        sni = str(tls_ev.get("sni") or "").strip().lower()
        alpn = str(tls_ev.get("alpn") or "").strip().lower()
        version = str(tls_ev.get("record_version") or tls_ev.get("version") or "").strip()
        if sni:
            patch["tls_sni"] = sni
        if alpn:
            patch["tls_alpn_first"] = alpn
        if version:
            patch["tls_version"] = version

    if agent_proto == "quic":
        patch["ja4_ptype"] = "q"
    elif agent_proto == "dtls":
        patch["ja4_ptype"] = "d"

    # Lightweight app proto guess (works even without payload).
    guess, confidence, reason = guess_application_proto(
        event_type=event_type,
        transport=proto,
        src_port=src_port,
        dst_port=dst_port,
        extra=extra,
    )
    if guess and not patch.get("app_proto"):
        patch["app_proto"] = guess
        patch["app_proto_confidence"] = confidence
        patch["app_proto_conf_band"] = confidence_band(confidence)
        patch["app_proto_reason"] = reason

    payload = extract_l7_bytes(extra, payload_max_bytes)

    # Protocol-aware parsing (only when we have enough bytes).
    if payload:
        if (patch.get("app_proto") == "dns") or (dst_port == 53 or src_port == 53):
            dns = parse_dns_message(payload)
            patch.update(dns)

        if (patch.get("app_proto") == "http") or (dst_port in (80, 8080, 8000, 8888) or src_port in (80, 8080, 8000, 8888)):
            http = parse_http_message(payload)
            patch.update(http)

        # TLS over TCP, DTLS, and QUIC (QUIC requires external extraction; we only consume TLS ClientHello bytes).
        if patch.get("app_proto") in ("tls", "quic", "dtls") or (dst_port in (443, 8443, 9443) or src_port in (443, 8443, 9443)):
            tls = parse_tls_client_hello(payload, extra=extra)
            patch.update(tls)

    # Marker to make the worker idempotent.
    if patch:
        patch["proto_intel_at"] = _utc_now_iso()

    return patch
