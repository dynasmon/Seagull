from __future__ import annotations

import os
from urllib.error import HTTPError, URLError

from .ipinfo import _build_ipinfo_record, _fetch_ipinfo
from .maxmind import _build_maxmind_record
from .normalization import (
    GEOIP_PROVIDER_AUTO,
    GEOIP_PROVIDER_IPINFO,
    GEOIP_PROVIDER_MAXMIND,
    GEOIP_PROVIDER_NONE,
    _env_str,
)


def _normalize_provider_name(value: str) -> str:
    normalized = (value or "").strip().lower()
    aliases = {
        "auto": GEOIP_PROVIDER_AUTO,
        "maxmind": GEOIP_PROVIDER_MAXMIND,
        "maxmind_local": GEOIP_PROVIDER_MAXMIND,
        "geolite2": GEOIP_PROVIDER_MAXMIND,
        "mmdb": GEOIP_PROVIDER_MAXMIND,
        "ipinfo": GEOIP_PROVIDER_IPINFO,
        "none": GEOIP_PROVIDER_NONE,
        "off": GEOIP_PROVIDER_NONE,
        "disabled": GEOIP_PROVIDER_NONE,
    }
    return aliases.get(normalized, GEOIP_PROVIDER_AUTO)


def _provider_config() -> dict[str, str]:
    return {
        "requested": _normalize_provider_name(
            _env_str(
                GEOIP_PROVIDER_AUTO,
                "SEAGULL_IP_INTEL_PROVIDER",
                "SEAGULL_LUPE_PROVIDER",
            )
        ),
        "fallback": _normalize_provider_name(
            _env_str(
                GEOIP_PROVIDER_NONE,
                "SEAGULL_IP_INTEL_FALLBACK_PROVIDER",
                "SEAGULL_LUPE_FALLBACK_PROVIDER",
            )
        ),
        "ipinfo_token": _env_str("", "SEAGULL_IPINFO_TOKEN"),
        "city_db_path": _env_str(
            "/app/data/geoip/GeoLite2-City.mmdb",
            "SEAGULL_IP_INTEL_MAXMIND_CITY_DB_PATH",
            "SEAGULL_GEOIP_CITY_DB_PATH",
            "SEAGULL_LUPE_MAXMIND_CITY_DB_PATH",
        ),
        "asn_db_path": _env_str(
            "/app/data/geoip/GeoLite2-ASN.mmdb",
            "SEAGULL_IP_INTEL_MAXMIND_ASN_DB_PATH",
            "SEAGULL_GEOIP_ASN_DB_PATH",
            "SEAGULL_LUPE_MAXMIND_ASN_DB_PATH",
        ),
    }


def _maxmind_paths_available(city_db_path: str, asn_db_path: str) -> tuple[bool, str]:
    city_exists = os.path.isfile(city_db_path)
    asn_exists = os.path.isfile(asn_db_path)
    if city_exists or asn_exists:
        return True, "mmdb_present"
    return False, "mmdb_missing"


def _provider_available(name: str, cfg: dict[str, str]) -> tuple[bool, str]:
    if name == GEOIP_PROVIDER_NONE:
        return False, "provider_disabled"
    if name == GEOIP_PROVIDER_MAXMIND:
        return _maxmind_paths_available(cfg["city_db_path"], cfg["asn_db_path"])
    if name == GEOIP_PROVIDER_IPINFO:
        if cfg["ipinfo_token"]:
            return True, "ipinfo_token_present"
        return False, "ipinfo_token_missing"
    return False, "provider_unknown"


def _resolve_provider(cfg: dict[str, str]) -> tuple[str, str]:
    requested = cfg["requested"]
    fallback = cfg["fallback"]

    if requested == GEOIP_PROVIDER_AUTO:
        for candidate in (GEOIP_PROVIDER_MAXMIND, GEOIP_PROVIDER_IPINFO):
            ok, reason = _provider_available(candidate, cfg)
            if ok:
                return candidate, f"auto:{reason}"
        return GEOIP_PROVIDER_NONE, "auto:no_provider_available"

    ok, reason = _provider_available(requested, cfg)
    if ok:
        return requested, reason

    if fallback != GEOIP_PROVIDER_NONE and fallback != requested:
        fallback_ok, fallback_reason = _provider_available(fallback, cfg)
        if fallback_ok:
            return fallback, f"fallback_from_{requested}:{fallback_reason}"

    return GEOIP_PROVIDER_NONE, f"requested_{requested}:{reason}"


def _lookup_ip(ip: str, provider_name: str, cfg: dict[str, str], timeout_s: float) -> dict:
    if provider_name == GEOIP_PROVIDER_MAXMIND:
        return _build_maxmind_record(ip, cfg["city_db_path"], cfg["asn_db_path"])
    if provider_name == GEOIP_PROVIDER_IPINFO:
        try:
            ipinfo = _fetch_ipinfo(ip, cfg["ipinfo_token"], timeout_s)
        except HTTPError as e:
            raise RuntimeError(f"ipinfo_http_error status={getattr(e, 'code', None)}") from e
        except URLError as e:
            raise RuntimeError("ipinfo_network_error") from e
        return _build_ipinfo_record(ipinfo)
    raise RuntimeError(f"ip_intel_provider_unavailable provider={provider_name}")
