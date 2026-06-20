from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

from app.core.config import settings

DEFAULT_PORT_HINTS: dict[int, tuple[str, int]] = {
    22: ("ssh", 85),
    23: ("telnet", 75),
    25: ("smtp", 80),
    53: ("dns", 90),
    67: ("dhcp", 80),
    68: ("dhcp", 80),
    80: ("http", 82),
    81: ("http", 70),
    88: ("kerberos", 78),
    110: ("pop3", 75),
    123: ("ntp", 80),
    135: ("msrpc", 70),
    137: ("netbios", 70),
    138: ("netbios", 70),
    139: ("smb", 78),
    143: ("imap", 75),
    161: ("snmp", 78),
    162: ("snmp", 78),
    389: ("ldap", 78),
    443: ("tls", 78),
    445: ("smb", 82),
    465: ("smtps", 78),
    500: ("ike", 78),
    514: ("syslog", 72),
    546: ("dhcpv6", 80),
    547: ("dhcpv6", 80),
    554: ("rtsp", 72),
    587: ("smtp", 80),
    631: ("ipp", 70),
    636: ("ldaps", 80),
    853: ("dot", 82),
    873: ("rsync", 68),
    993: ("imaps", 80),
    995: ("pop3s", 80),
    1194: ("openvpn", 80),
    1433: ("mssql", 80),
    1521: ("oracle", 78),
    1883: ("mqtt", 80),
    2049: ("nfs", 78),
    2375: ("docker", 74),
    2376: ("docker-tls", 76),
    2379: ("etcd", 74),
    2380: ("etcd", 74),
    3000: ("grafana", 70),
    3128: ("http-proxy", 72),
    3306: ("mysql", 80),
    3389: ("rdp", 84),
    5353: ("mdns", 80),
    5355: ("llmnr", 76),
    5432: ("postgresql", 82),
    5671: ("amqps", 78),
    5672: ("amqp", 78),
    5683: ("coap", 80),
    5684: ("coaps", 80),
    5900: ("vnc", 78),
    5901: ("vnc", 78),
    6379: ("redis", 82),
    6443: ("kube-apiserver", 78),
    6514: ("syslog-tls", 74),
    7474: ("neo4j-http", 70),
    7687: ("bolt", 72),
    8000: ("http", 75),
    8080: ("http", 75),
    8443: ("https-alt", 76),
    8500: ("consul", 72),
    8883: ("mqtts", 80),
    8888: ("http", 75),
    9090: ("prometheus", 70),
    9092: ("kafka", 78),
    9093: ("kafka-tls", 78),
    9200: ("elasticsearch", 74),
    9418: ("git", 72),
    9443: ("https-alt", 76),
    11211: ("memcached", 76),
    27017: ("mongodb", 82),
    51820: ("wireguard", 84),
}


def _parse_int_set(raw: str) -> set[int]:
    out: set[int] = set()
    for token in raw.replace("|", ",").replace("/", ",").split(","):
        s = token.strip()
        if not s:
            continue
        try:
            p = int(s)
        except ValueError:
            continue
        if 1 <= p <= 65535:
            out.add(p)
    return out


@lru_cache(maxsize=1)
def _env_port_hints() -> dict[int, tuple[str, int]]:

    raw = (settings.SEAGULL_PROTO_INTEL_PORT_HINTS or "").strip()
    if not raw:
        return {}

    out: dict[int, tuple[str, int]] = {}
    chunks = [c.strip() for c in raw.replace("\n", ";").split(";") if c.strip()]
    for c in chunks:
        sep = ":" if ":" in c else "=" if "=" in c else None
        if not sep:
            continue
        proto_part, ports_part = c.split(sep, 1)
        proto = proto_part.strip().lower().replace(" ", "_")
        if not proto:
            continue
        for p in _parse_int_set(ports_part):
            out[p] = (proto, 92)
    return out


def confidence_band(confidence: int) -> str:
    c = max(0, min(100, int(confidence)))
    if c >= 80:
        return "80-100"
    if c >= 60:
        return "60-79"
    if c >= 40:
        return "40-59"
    return "0-39"


def guess_application_proto(
    *,
    event_type: str,
    transport: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    extra: Dict[str, Any],
) -> Tuple[Optional[str], int, str]:

    et = (event_type or "").lower().strip()
    tr = (transport or "").lower().strip()

    # Agent-provided hints (future-proof).
    if bool(extra.get("is_quic")) or (str(extra.get("ja4_ptype") or "").lower() == "q"):
        return "quic", 95, "extra_hint"
    if bool(extra.get("is_dtls")) or (str(extra.get("ja4_ptype") or "").lower() == "d"):
        return "dtls", 95, "extra_hint"
    if extra.get("l7_protocol"):
        return str(extra.get("l7_protocol")).strip().lower(), 97, "agent_l7_protocol"
    if extra.get("dns_qname"):
        return "dns", 98, "parsed_dns"
    if extra.get("http_method") or extra.get("http_host") or extra.get("http_status"):
        return "http", 98, "parsed_http"
    if extra.get("tls_sni") or extra.get("ja4") or extra.get("ja3"):
        return "tls", 98, "parsed_tls"

    sp = int(src_port) if isinstance(src_port, int) else None
    dp = int(dst_port) if isinstance(dst_port, int) else None

    ports = {p for p in (sp, dp) if isinstance(p, int) and p > 0}

    if et.startswith("ssh") or et == "sudo_cmd":
        return "ssh", 80, "ssh_signal"
    if et.startswith("dns"):
        return "dns", 85, "event_type_dns"
    if et.startswith("http"):
        return "http", 85, "event_type_http"
    if et.startswith("tls") or et.startswith("quic"):
        return "tls", 85, "event_type_tls"

    # Transport-specific defaults.
    if tr.startswith("udp") and 443 in ports:
        return "quic", 86, "udp_443"
    if tr.startswith("udp") and 853 in ports:
        return "dot", 85, "udp_853"

    env_hints = _env_port_hints()

    best_proto: Optional[str] = None
    best_conf = -1
    best_reason = "unknown"

    for p in ports:
        env_hit = env_hints.get(p)
        if env_hit:
            proto_name, conf = env_hit
            if conf > best_conf:
                best_proto, best_conf, best_reason = proto_name, conf, f"env_port_{p}"
            continue

        built = DEFAULT_PORT_HINTS.get(p)
        if built:
            proto_name, conf = built
            # UDP 443 is often QUIC; prefer it over generic TLS signal.
            if p == 443 and tr.startswith("udp"):
                proto_name, conf = "quic", 86
            if conf > best_conf:
                best_proto, best_conf, best_reason = proto_name, conf, f"port_{p}"

    if best_proto is not None:
        return best_proto, best_conf, best_reason

    if et in ("flow", "scan_probe", "lateral_conn"):
        return "flow", 30, "generic_flow"

    return None, 0, "unknown"
