from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from typing import Any

logger = logging.getLogger("seagull.shared.network.ip_classification")

# ---- Built-in IPv4 special ranges ------------------------------------------------

_V4_LINK_LOCAL = ipaddress.IPv4Network("169.254.0.0/16")
_V4_CGNAT = ipaddress.IPv4Network("100.64.0.0/10")
_V4_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_V4_DOCUMENTATION = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)

# ---- Built-in IPv6 special ranges ------------------------------------------------

_V6_LINK_LOCAL = ipaddress.IPv6Network("fe80::/10")
_V6_UNIQUE_LOCAL = ipaddress.IPv6Network("fc00::/7")
_V6_DOCUMENTATION = ipaddress.IPv6Network("2001:db8::/32")

# ---- Labels and scope metadata ---------------------------------------------------

_SCOPE_LABELS: dict[str, str] = {
    "public_internet": "Public",
    "internal_network": "Internal",
    "private_address": "Private",
    "loopback": "Loopback",
    "link_local": "Link-Local",
    "cgnat": "CGNAT",
    "multicast": "Multicast",
    "unspecified": "Unspecified",
    "documentation": "Documentation",
    "reserved": "Reserved",
    "unique_local": "Unique-Local",
    "invalid": "Invalid",
    "unknown": "Unknown",
}

_INTERNAL_SCOPES: frozenset[str] = frozenset({
    "internal_network",
    "private_address",
    "loopback",
    "link_local",
    "cgnat",
    "unique_local",
})

_SPECIAL_SCOPES: frozenset[str] = frozenset({
    "multicast",
    "unspecified",
    "documentation",
    "reserved",
})


# ---- CIDR parsing ----------------------------------------------------------------

@lru_cache(maxsize=64)
def _parse_cidrs_cached(
    cidrs_tuple: tuple[str, ...],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    result: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in cidrs_tuple:
        try:
            result.append(ipaddress.ip_network(raw, strict=False))
        except Exception:
            pass  # invalid entries silently dropped; caller handles logging
    return tuple(result)


def parse_internal_cidrs(
    raw: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse and validate a list of CIDR strings. Invalid entries are logged and skipped."""
    cleaned = [str(s).strip() for s in raw if str(s).strip()]
    if not cleaned:
        return []
    # Log warnings outside the cache so they appear on every call with bad input.
    for s in cleaned:
        try:
            ipaddress.ip_network(s, strict=False)
        except Exception:
            logger.warning("SEAGULL_INTERNAL_NETWORK_CIDRS: ignoring invalid CIDR %r", s)
    return list(_parse_cidrs_cached(tuple(cleaned)))


# ---- Result builder --------------------------------------------------------------

def _result(
    ip: str,
    version: int,
    scope: str,
    *,
    matched_cidr: str | None = None,
    match_source: str | None = None,
) -> dict[str, Any]:
    return {
        "ip": ip,
        "version": version,
        "scope": scope,
        "label": _SCOPE_LABELS.get(scope, scope),
        "is_internal": scope in _INTERNAL_SCOPES,
        "is_public": scope == "public_internet",
        "is_special": scope in _SPECIAL_SCOPES,
        "matched_cidr": matched_cidr,
        "match_source": match_source,
    }


# ---- Core classifier -------------------------------------------------------------

def classify_ip(
    ip: str | None,
    *,
    internal_cidrs: list[str] | None = None,
) -> dict[str, Any]:
    """Classify an IP address string and return a structured result dict.

    Configured internal_cidrs take precedence over all built-in range checks.
    Invalid CIDR entries in internal_cidrs are logged and silently ignored.
    """
    raw = str(ip or "").strip()
    if not raw:
        return _result("", 0, "invalid")

    try:
        addr = ipaddress.ip_address(raw)
    except Exception:
        return _result(raw, 0, "invalid")

    version = addr.version

    # Configured internal CIDRs win over all built-in classification.
    if internal_cidrs:
        for net in parse_internal_cidrs(internal_cidrs):
            if addr in net:
                return _result(
                    raw, version, "internal_network",
                    matched_cidr=str(net),
                    match_source="configured_cidr",
                )

    if addr.is_unspecified:
        return _result(raw, version, "unspecified", match_source="builtin")

    if addr.is_loopback:
        cidr = "127.0.0.0/8" if version == 4 else "::1/128"
        return _result(raw, version, "loopback", matched_cidr=cidr, match_source="builtin")

    if addr.is_multicast:
        cidr = "224.0.0.0/4" if version == 4 else "ff00::/8"
        return _result(raw, version, "multicast", matched_cidr=cidr, match_source="builtin")

    if version == 4:
        v4 = ipaddress.IPv4Address(addr)

        if v4 in _V4_LINK_LOCAL:
            return _result(raw, 4, "link_local", matched_cidr="169.254.0.0/16", match_source="builtin")

        if v4 in _V4_CGNAT:
            return _result(raw, 4, "cgnat", matched_cidr="100.64.0.0/10", match_source="builtin")

        for doc_net in _V4_DOCUMENTATION:
            if v4 in doc_net:
                return _result(raw, 4, "documentation", matched_cidr=str(doc_net), match_source="builtin")

        for rfc_net in _V4_RFC1918:
            if v4 in rfc_net:
                return _result(raw, 4, "private_address", matched_cidr=str(rfc_net), match_source="builtin")

        if addr.is_reserved:
            return _result(raw, 4, "reserved", match_source="builtin")

        if addr.is_global:
            return _result(raw, 4, "public_internet", match_source="builtin")

        return _result(raw, 4, "unknown")

    else:
        v6 = ipaddress.IPv6Address(addr)

        if v6 in _V6_LINK_LOCAL:
            return _result(raw, 6, "link_local", matched_cidr="fe80::/10", match_source="builtin")

        if v6 in _V6_DOCUMENTATION:
            return _result(raw, 6, "documentation", matched_cidr="2001:db8::/32", match_source="builtin")

        if v6 in _V6_UNIQUE_LOCAL:
            return _result(raw, 6, "unique_local", matched_cidr="fc00::/7", match_source="builtin")

        if addr.is_reserved:
            return _result(raw, 6, "reserved", match_source="builtin")

        if addr.is_global:
            return _result(raw, 6, "public_internet", match_source="builtin")

        return _result(raw, 6, "unknown")


# ---- Flow-level helper -----------------------------------------------------------

def classify_flow(
    src_ip: str | None,
    dst_ip: str | None,
    *,
    internal_cidrs: list[str] | None = None,
) -> dict[str, Any]:
    """Classify a src→dst flow and compute locality."""
    src = classify_ip(src_ip, internal_cidrs=internal_cidrs)
    dst = classify_ip(dst_ip, internal_cidrs=internal_cidrs)

    src_missing = not str(src_ip or "").strip() or src["scope"] == "invalid"
    dst_missing = not str(dst_ip or "").strip() or dst["scope"] == "invalid"

    src_internal = src["is_internal"]
    dst_internal = dst["is_internal"]
    src_public = src["is_public"]
    dst_public = dst["is_public"]

    if src_missing or dst_missing:
        locality = "unknown"
    elif src_public and dst_public:
        locality = "public_to_public"
    elif src_public and dst_internal:
        locality = "public_to_internal"
    elif src_internal and dst_public:
        locality = "internal_to_public"
    elif src_internal and dst_internal:
        locality = "internal_to_internal"
    else:
        locality = "private_or_special"

    return {
        "src": src,
        "dst": dst,
        "flow": {
            "locality": locality,
            "src_internal": src_internal,
            "dst_internal": dst_internal,
            "external_to_internal": src_public and dst_internal,
            "internal_to_internal": src_internal and dst_internal,
            "internal_to_public": src_internal and dst_public,
        },
    }
