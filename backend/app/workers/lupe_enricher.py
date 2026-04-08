"""Lupe enrichment worker.

Enriches SSH auth events (event_type='ssh_auth') with Geo/ASN metadata.

Primary provider:
- MaxMind GeoLite2 local MMDB databases (no per-request external rate limit)

Optional fallback provider:
- IPinfo HTTP API

Writes into net_events.extra (only when missing):
- geo_country, geo_region, geo_city, geo_loc
- geo_org
- asn, asn_org
- ip_intel_provider
- lupe_enriched_at (RFC3339 UTC)

Cache:
- ip_enrichment_cache (Postgres) to avoid repeated lookups.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import OperationalError

from app.core.config import settings
from app.core.db import engine
from app.core.db_lifecycle import ensure_database_ready
from app.core.observability import log_event, setup_logging
from app.features.events.worker_runtime import NetEventModel
from app.shared.enrichment.models import IpEnrichmentCacheModel
from app.shared.indexing.offset_store import ensure_offset, get_offset, set_offset


OFFSET_LUPE = "lupe_enricher_ssh_v1"
setup_logging("worker-lupe")
logger = logging.getLogger("netwatch.worker.lupe")

# Only enrich these actions (accepted, failed_password, invalid_user). This matches the Lupe intent.
SSH_ACTIONS: tuple[str, ...] = ("accepted", "failed_password", "invalid_user")

ASN_RE = re.compile(r"^(AS\d+)\s+(.*)$")

GEOIP_PROVIDER_AUTO = "auto"
GEOIP_PROVIDER_MAXMIND = "maxmind_local"
GEOIP_PROVIDER_IPINFO = "ipinfo"
GEOIP_PROVIDER_NONE = "none"

_GEOIP_CITY_READER = None
_GEOIP_ASN_READER = None
_GEOIP_CITY_PATH: Optional[str] = None
_GEOIP_ASN_PATH: Optional[str] = None


def _env_raw(*names: str) -> Optional[str]:
    for name in names:
        raw = os.getenv(name)
        if raw is None:
            continue
        value = raw.strip()
        if value == "":
            continue
        return value
    return None


def _env_str(default: str, *names: str) -> str:
    value = _env_raw(*names)
    return value if value is not None else default


def _env_int(default: int, *names: str) -> int:
    value = _env_raw(*names)
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _env_float(default: float, *names: str) -> float:
    value = _env_raw(*names)
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_unspecified or obj.is_reserved:
        return False
    return True


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        out[k] = v
    return out


def _parse_asn(org: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not org:
        return None, None
    m = ASN_RE.match(org.strip())
    if not m:
        return None, org.strip()
    return m.group(1), m.group(2).strip()


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
                "NETWATCH_IP_INTEL_PROVIDER",
                "NETWATCH_LUPE_PROVIDER",
            )
        ),
        "fallback": _normalize_provider_name(
            _env_str(
                GEOIP_PROVIDER_NONE,
                "NETWATCH_IP_INTEL_FALLBACK_PROVIDER",
                "NETWATCH_LUPE_FALLBACK_PROVIDER",
            )
        ),
        "ipinfo_token": _env_str("", "NETWATCH_IPINFO_TOKEN"),
        "city_db_path": _env_str(
            "/app/data/geoip/GeoLite2-City.mmdb",
            "NETWATCH_IP_INTEL_MAXMIND_CITY_DB_PATH",
            "NETWATCH_GEOIP_CITY_DB_PATH",
            "NETWATCH_LUPE_MAXMIND_CITY_DB_PATH",
        ),
        "asn_db_path": _env_str(
            "/app/data/geoip/GeoLite2-ASN.mmdb",
            "NETWATCH_IP_INTEL_MAXMIND_ASN_DB_PATH",
            "NETWATCH_GEOIP_ASN_DB_PATH",
            "NETWATCH_LUPE_MAXMIND_ASN_DB_PATH",
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


def _ensure_bootstrap(default_ttl_days: int) -> None:
    """Self-healing bootstrap.

    The backend runs schema_bootstrap at startup, but workers may start first.
    """
    ensure_database_ready()
    with engine.begin() as conn:
        ensure_offset(OFFSET_LUPE, conn=conn)
        conn.execute(
            update(IpEnrichmentCacheModel)
            .where(IpEnrichmentCacheModel.expires_at.is_(None))
            .values(expires_at=_utc_now() + timedelta(days=int(default_ttl_days)))
        )


def _get_last_id() -> int:
    return get_offset(OFFSET_LUPE)


def _set_last_id(last_id: int) -> None:
    set_offset(OFFSET_LUPE, last_id)


def _pick_batch_max_id(last_id: int, max_rows: int) -> Optional[int]:
    with engine.begin() as conn:
        subq = (
            select(NetEventModel.id)
            .where(NetEventModel.id > int(last_id))
            .order_by(NetEventModel.id.asc())
            .limit(int(max_rows))
            .subquery()
        )
        row = conn.execute(select(func.max(subq.c.id))).fetchone()
        v = row[0] if row else None
        return int(v) if v is not None else None


def _fetch_batch(last_id: int, max_id: int, limit: int) -> list[dict]:
    with engine.begin() as conn:
        rows = conn.execute(
            select(
                NetEventModel.id,
                NetEventModel.agent_id,
                NetEventModel.src_ip,
                NetEventModel.extra["action"].astext.label("action"),
            )
            .where(
                NetEventModel.id > int(last_id),
                NetEventModel.id <= int(max_id),
                NetEventModel.event_type == "ssh_auth",
                NetEventModel.src_ip.is_not(None),
                NetEventModel.extra["action"].astext.in_(list(SSH_ACTIONS)),
                ~NetEventModel.extra.has_key("lupe_enriched_at"),
            )
            .order_by(NetEventModel.id.asc())
            .limit(int(limit))
        ).mappings().all()
        return [dict(r) for r in rows]


def _get_cached_ip(ip: str) -> Optional[dict]:
    with engine.begin() as conn:
        row = conn.execute(
            select(
                IpEnrichmentCacheModel.country,
                IpEnrichmentCacheModel.region,
                IpEnrichmentCacheModel.city,
                IpEnrichmentCacheModel.loc,
                IpEnrichmentCacheModel.org,
                IpEnrichmentCacheModel.asn,
                IpEnrichmentCacheModel.asn_org,
                IpEnrichmentCacheModel.data,
                IpEnrichmentCacheModel.expires_at,
            )
            .where(IpEnrichmentCacheModel.ip == ip)
            .limit(1)
        ).mappings().fetchone()
        if not row:
            return None
        expires_at = row.get("expires_at")
        if expires_at is not None:
            try:
                if expires_at <= _utc_now():
                    return None
            except Exception:
                return None
        data = row.get("data") or {}
        return {
            "country": row.get("country"),
            "region": row.get("region"),
            "city": row.get("city"),
            "loc": row.get("loc"),
            "org": row.get("org"),
            "asn": row.get("asn"),
            "asn_org": row.get("asn_org"),
            "data": data,
            "provider": data.get("provider") if isinstance(data, dict) else None,
        }


def _upsert_cache(ip: str, rec: dict, ttl_days: int) -> None:
    expires_at = _utc_now() + timedelta(days=int(ttl_days))
    with engine.begin() as conn:
        ins = insert(IpEnrichmentCacheModel).values(
            ip=ip,
            country=rec.get("country"),
            region=rec.get("region"),
            city=rec.get("city"),
            loc=rec.get("loc"),
            org=rec.get("org"),
            asn=rec.get("asn"),
            asn_org=rec.get("asn_org"),
            data=rec.get("data") or {},
            fetched_at=_utc_now(),
            expires_at=expires_at,
        )
        conn.execute(
            ins.on_conflict_do_update(
                index_elements=[IpEnrichmentCacheModel.ip],
                set_={
                    "country": ins.excluded.country,
                    "region": ins.excluded.region,
                    "city": ins.excluded.city,
                    "loc": ins.excluded.loc,
                    "org": ins.excluded.org,
                    "asn": ins.excluded.asn,
                    "asn_org": ins.excluded.asn_org,
                    "data": ins.excluded.data,
                    "fetched_at": _utc_now(),
                    "expires_at": ins.excluded.expires_at,
                },
            )
        )


def _fetch_ipinfo(ip: str, token: str, timeout_s: float) -> dict:
    url = f"https://ipinfo.io/{ip}/json?token={token}"
    req = Request(url, headers={"User-Agent": "netwatch-lupe/1.0"})
    with urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def _build_ipinfo_record(ipinfo: dict) -> dict:
    country = ipinfo.get("country")
    region = ipinfo.get("region")
    city = ipinfo.get("city")
    loc = ipinfo.get("loc")
    org = ipinfo.get("org")
    asn, asn_org = _parse_asn(org)

    return {
        "country": country,
        "region": region,
        "city": city,
        "loc": loc,
        "org": org,
        "asn": asn,
        "asn_org": asn_org,
        "provider": GEOIP_PROVIDER_IPINFO,
        "data": {
            "provider": GEOIP_PROVIDER_IPINFO,
            "raw": ipinfo,
        },
    }


def _close_geoip_reader(reader) -> None:
    if reader is None:
        return
    try:
        reader.close()
    except Exception:
        return


def _ensure_geoip_readers(city_db_path: str, asn_db_path: str) -> None:
    global _GEOIP_CITY_READER, _GEOIP_ASN_READER, _GEOIP_CITY_PATH, _GEOIP_ASN_PATH

    try:
        import geoip2.database  # type: ignore
    except Exception as e:
        raise RuntimeError("geoip2_dependency_missing") from e

    if city_db_path != _GEOIP_CITY_PATH:
        _close_geoip_reader(_GEOIP_CITY_READER)
        _GEOIP_CITY_READER = None
        _GEOIP_CITY_PATH = city_db_path
    if asn_db_path != _GEOIP_ASN_PATH:
        _close_geoip_reader(_GEOIP_ASN_READER)
        _GEOIP_ASN_READER = None
        _GEOIP_ASN_PATH = asn_db_path

    if _GEOIP_CITY_READER is None and os.path.isfile(city_db_path):
        _GEOIP_CITY_READER = geoip2.database.Reader(city_db_path)
    if _GEOIP_ASN_READER is None and os.path.isfile(asn_db_path):
        _GEOIP_ASN_READER = geoip2.database.Reader(asn_db_path)


def _build_maxmind_record(ip: str, city_db_path: str, asn_db_path: str) -> dict:
    _ensure_geoip_readers(city_db_path, asn_db_path)

    country = None
    region = None
    city = None
    loc = None
    org = None
    asn = None
    asn_org = None
    raw: dict[str, Any] = {"provider": GEOIP_PROVIDER_MAXMIND, "ip": ip}

    if _GEOIP_CITY_READER is not None:
        try:
            city_resp = _GEOIP_CITY_READER.city(ip)
        except Exception:
            city_resp = None
        if city_resp is not None:
            country = getattr(getattr(city_resp, "country", None), "iso_code", None) or getattr(
                getattr(city_resp, "registered_country", None),
                "iso_code",
                None,
            )
            subdivisions = getattr(city_resp, "subdivisions", None)
            if subdivisions is not None:
                region = getattr(getattr(subdivisions, "most_specific", None), "name", None)
            city = getattr(getattr(city_resp, "city", None), "name", None)
            location = getattr(city_resp, "location", None)
            latitude = getattr(location, "latitude", None)
            longitude = getattr(location, "longitude", None)
            if latitude is not None and longitude is not None:
                loc = f"{latitude},{longitude}"
            raw["city"] = {
                "country": country,
                "region": region,
                "city": city,
                "loc": loc,
            }

    if _GEOIP_ASN_READER is not None:
        try:
            asn_resp = _GEOIP_ASN_READER.asn(ip)
        except Exception:
            asn_resp = None
        if asn_resp is not None:
            asn_number = getattr(asn_resp, "autonomous_system_number", None)
            asn_org = getattr(asn_resp, "autonomous_system_organization", None)
            asn = f"AS{asn_number}" if asn_number is not None else None
            org = asn_org or org
            raw["asn"] = {
                "asn": asn,
                "asn_org": asn_org,
            }

    return {
        "country": country,
        "region": region,
        "city": city,
        "loc": loc,
        "org": org,
        "asn": asn,
        "asn_org": asn_org,
        "provider": GEOIP_PROVIDER_MAXMIND,
        "data": raw,
    }


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


def _patch_event(event_id: int, patch: dict) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(NetEventModel)
            .where(NetEventModel.id == int(event_id))
            .values(extra=NetEventModel.extra.op("||")(patch))
        )


def main() -> None:
    settings.validate_for_service("worker-ip-intel")

    every_s = _env_float(1.0, "NETWATCH_IP_INTEL_EVERY_SECONDS", "NETWATCH_LUPE_EVERY_SECONDS")
    idle_sleep_s = _env_float(2.0, "NETWATCH_IP_INTEL_IDLE_SLEEP_SECONDS", "NETWATCH_LUPE_IDLE_SLEEP_SECONDS")
    max_rows = _env_int(2000, "NETWATCH_IP_INTEL_MAX_ROWS", "NETWATCH_LUPE_MAX_ROWS")
    batch_size = _env_int(200, "NETWATCH_IP_INTEL_BATCH_SIZE", "NETWATCH_LUPE_BATCH_SIZE")
    timeout_s = _env_float(8.0, "NETWATCH_IP_INTEL_HTTP_TIMEOUT_SECONDS", "NETWATCH_LUPE_HTTP_TIMEOUT_SECONDS")
    cache_ttl_days = _env_int(7, "NETWATCH_IP_INTEL_CACHE_TTL_DAYS", "NETWATCH_LUPE_CACHE_TTL_DAYS")
    skip_private = (
        _env_str("true", "NETWATCH_IP_INTEL_SKIP_PRIVATE", "NETWATCH_LUPE_SKIP_PRIVATE").strip().lower() != "false"
    )

    backoff = 1.0
    last_provider_state: Optional[tuple[str, str]] = None

    while True:
        try:
            _ensure_bootstrap(cache_ttl_days)

            cfg = _provider_config()
            provider_name, provider_reason = _resolve_provider(cfg)
            provider_state = (provider_name, provider_reason)
            if provider_state != last_provider_state:
                level = "info" if provider_name != GEOIP_PROVIDER_NONE else "warning"
                log_event(
                    logger,
                    level,
                    "ip_intel_provider_selected",
                    provider=provider_name,
                    reason=provider_reason,
                    requested=cfg["requested"],
                    fallback=cfg["fallback"],
                )
                last_provider_state = provider_state

            if provider_name == GEOIP_PROVIDER_NONE:
                time.sleep(max(idle_sleep_s, 2.0))
                continue

            last_id = _get_last_id()
            max_id = _pick_batch_max_id(last_id, max_rows)

            if max_id is None or max_id <= last_id:
                time.sleep(idle_sleep_s)
                backoff = 1.0
                continue

            rows = _fetch_batch(last_id, max_id, batch_size)
            if not rows:
                _set_last_id(max_id)
                time.sleep(max(every_s, 0.1))
                backoff = 1.0
                continue

            last_done_id = last_id
            t0 = time.time()

            for r in rows:
                eid = int(r["id"])
                ip = (r.get("src_ip") or "").strip()

                base_patch = {
                    "lupe_enriched_at": _utc_now().isoformat().replace("+00:00", "Z"),
                }

                if not ip:
                    _patch_event(eid, {**base_patch, "lupe_skipped": True, "lupe_reason": "missing_src_ip"})
                    last_done_id = eid
                    continue

                if skip_private and not _is_public_ip(ip):
                    _patch_event(eid, {**base_patch, "lupe_skipped": True, "lupe_reason": "non_public_ip"})
                    last_done_id = eid
                    continue

                cached = _get_cached_ip(ip)
                if cached is None:
                    rec = _lookup_ip(ip, provider_name, cfg, timeout_s)
                    _upsert_cache(ip, rec, cache_ttl_days)
                    cached = rec

                patch = _compact(
                    {
                        **base_patch,
                        "geo_country": cached.get("country"),
                        "geo_region": cached.get("region"),
                        "geo_city": cached.get("city"),
                        "geo_loc": cached.get("loc"),
                        "geo_org": cached.get("org"),
                        "asn": cached.get("asn"),
                        "asn_org": cached.get("asn_org"),
                        "ip_intel_provider": cached.get("provider") or provider_name,
                    }
                )

                _patch_event(eid, patch)
                last_done_id = eid

            _set_last_id(last_done_id)
            took_ms = int((time.time() - t0) * 1000)
            log_event(
                logger,
                "info",
                "lupe_ok",
                last_id=last_id,
                max_id=max_id,
                processed=len(rows),
                provider=provider_name,
                took_ms=took_ms,
            )

            backoff = 1.0
            time.sleep(max(every_s, 0.1))

        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            log_event(logger, "warning", "lupe_db_not_ready", wait_s=wait_s, error=str(e).splitlines()[0])
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 30.0)
            log_event(logger, "error", "lupe_loop_error", wait_s=wait_s, error=repr(e))
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
