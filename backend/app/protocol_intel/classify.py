from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


def guess_application_proto(
    *,
    event_type: str,
    transport: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    extra: Dict[str, Any],
) -> Tuple[Optional[str], int, str]:
    """Best-effort classification using stable signals.

    Returns: (app_proto, confidence 0..100, reason)

    Signals:
    - explicit hints in extra: is_quic/is_dtls/transport
    - transport+ports
    - event_type (agent-specific)

    This is intentionally conservative; deep parsing happens elsewhere.
    """

    et = (event_type or "").lower()
    tr = (transport or "").lower()

    # Agent-provided hints (future-proof).
    if bool(extra.get("is_quic")) or (str(extra.get("ja4_ptype") or "").lower() == "q"):
        return "quic", 95, "extra_hint"
    if bool(extra.get("is_dtls")) or (str(extra.get("ja4_ptype") or "").lower() == "d"):
        return "dtls", 95, "extra_hint"

    sp = int(src_port) if isinstance(src_port, int) else None
    dp = int(dst_port) if isinstance(dst_port, int) else None

    ports = {p for p in (sp, dp) if isinstance(p, int) and p > 0}

    if 53 in ports:
        return "dns", 80, "port_53"

    if 22 in ports or et.startswith("ssh") or et == "sudo_cmd":
        return "ssh", 80, "ssh_signal"

    if 80 in ports or 8080 in ports or 8000 in ports or 8888 in ports:
        return "http", 70, "http_port"

    if 443 in ports or 8443 in ports:
        # UDP 443 is often QUIC, but we keep it as tls unless we have a QUIC hint.
        if tr.startswith("udp"):
            return "quic", 55, "udp_443"
        return "tls", 70, "tls_port"

    if tr.startswith("udp") and 500 in ports:
        return "ike", 50, "udp_500"

    if et in ("flow", "scan_probe", "lateral_conn"):
        return "flow", 30, "generic_flow"

    return None, 0, "unknown"
