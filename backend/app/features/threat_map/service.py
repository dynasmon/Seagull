from __future__ import annotations

import json
import os
import time
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.core.cache import get_json, set_json
from app.core.config import settings
from app.features.threat_map import repository
from app.features.threat_map.schemas import (
    ThreatGeoEndpoint,
    ThreatGeoFlow,
    ThreatGeoIp,
    ThreatGeoMeta,
    ThreatGeoPoint,
    ThreatGeoRankCountry,
    ThreatGeoRankIp,
    ThreatGeoResponse,
    ThreatGeoRuleCount,
)
from app.shared.network.ip_classification import classify_ip

CLUSTER_PRECISION = 1
TOP_IPS_PER_POINT = 6
TOP_RULES_PER_POINT = 6
TOP_RANK = 8
FLOW_LIMIT = 60

VALID_SOURCES = ("both", "events", "alerts")

HOME_CACHE_KEY = "seagull:threat_map:home:v1"
HOME_CACHE_TTL_SECONDS = 3600
HOME_MISS_TTL_SECONDS = 300
HOME_LOOKUP_URL = "https://ipinfo.io/json"
HOME_LOOKUP_TIMEOUT_SECONDS = 4.0


def _cache_get_json(key: str) -> dict[str, Any] | None:
    return get_json(key)


def _cache_set_json(key: str, payload: dict[str, Any], ttl_s: int) -> None:
    set_json(key, payload, ttl_s)


def _fetch_self_geo() -> Optional[dict[str, Any]]:
    token = (os.environ.get("SEAGULL_IPINFO_TOKEN") or "").strip()
    url = f"{HOME_LOOKUP_URL}?token={token}" if token else HOME_LOOKUP_URL
    try:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "seagull-threat-map"},
        )
        with urllib.request.urlopen(request, timeout=HOME_LOOKUP_TIMEOUT_SECONDS) as response:
            return json.load(response)
    except Exception:
        return None


def _resolve_home_endpoint() -> Optional[ThreatGeoEndpoint]:
    label_override = _clean_text(os.environ.get("SEAGULL_THREAT_MAP_HOME_LABEL"))
    latlon_override = (os.environ.get("SEAGULL_THREAT_MAP_HOME_LATLON") or "").strip()
    if latlon_override:
        coords = repository.parse_loc(latlon_override)
        if coords:
            return ThreatGeoEndpoint(lat=coords[0], lon=coords[1], label=label_override or "Home network", scope="home")

    cached = _cache_get_json(HOME_CACHE_KEY)
    if isinstance(cached, dict):
        if cached.get("miss"):
            return None
        if cached.get("lat") is not None and cached.get("lon") is not None:
            return ThreatGeoEndpoint(
                lat=cached["lat"],
                lon=cached["lon"],
                city=cached.get("city"),
                region=cached.get("region"),
                country=cached.get("country"),
                label=cached.get("label"),
                scope="home",
            )

    info = _fetch_self_geo()
    coords = repository.parse_loc((info or {}).get("loc"))
    if not info or not coords:
        _cache_set_json(HOME_CACHE_KEY, {"miss": True}, HOME_MISS_TTL_SECONDS)
        return None

    endpoint = ThreatGeoEndpoint(
        lat=coords[0],
        lon=coords[1],
        city=_clean_text(info.get("city")),
        region=_clean_text(info.get("region")),
        country=_clean_text(info.get("country")),
        label=label_override or _location_label(info.get("city"), info.get("region"), info.get("country")),
        scope="home",
    )
    _cache_set_json(HOME_CACHE_KEY, endpoint.dict(), HOME_CACHE_TTL_SECONDS)
    return endpoint


def _worst_severity(critical: int, high: int, medium: int, low: int) -> str:
    if critical > 0:
        return "critical"
    if high > 0:
        return "high"
    if medium > 0:
        return "medium"
    if low > 0:
        return "low"
    return "unknown"


def _mode(counter: Counter) -> Optional[str]:
    return counter.most_common(1)[0][0] if counter else None


def _clean_text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip()
    return value or None


def _as_utc(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return value


def _location_label(city: Any, region: Any, country: Any) -> str:
    place = _clean_text(city) or _clean_text(region)
    cc = (_clean_text(country) or "").upper()
    if place and cc:
        return f"{place} · {cc}"
    return place or cc or "Unknown location"


def _normalize_source_rows(rows: list[Any], *, provenance: str, direction: str) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for row in rows:
        ip = str(row.get("src_ip") or "").strip()
        if not ip:
            continue
        normalized.append(
            {
                "src_ip": ip,
                "count": int(row.get("count", 0) or 0),
                "critical": int(row.get("critical", 0) or 0),
                "high": int(row.get("high", 0) or 0),
                "medium": int(row.get("medium", 0) or 0),
                "low": int(row.get("low", 0) or 0),
                "last_seen": _as_utc(row.get("last_seen")),
                "provenance": provenance,
                "direction": direction,
            }
        )
    return normalized


def _expand_dos_sources(rows: list[Any]) -> list[dict[str, Any]]:
    accumulator: dict[str, dict[str, Any]] = {}
    for row in rows:
        top_src = row.get("top_src")
        if not isinstance(top_src, list):
            continue
        last_seen = row.get("last_seen")
        for item in top_src:
            if not isinstance(item, dict):
                continue
            ip = str(item.get("ip") or "").strip()
            if not ip:
                continue
            weight = max(int(item.get("packets", 0) or 0), 1)
            entry = accumulator.get(ip)
            if entry is None:
                entry = accumulator[ip] = {
                    "src_ip": ip,
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "last_seen": last_seen,
                }
            entry["count"] += weight
            entry["high"] += weight
            if last_seen is not None and (entry["last_seen"] is None or last_seen > entry["last_seen"]):
                entry["last_seen"] = last_seen
    return list(accumulator.values())


def _extra_geo_record(
    *,
    loc: Any,
    country: Any = None,
    region: Any = None,
    city: Any = None,
    org: Any = None,
    asn: Any = None,
    asn_org: Any = None,
) -> Optional[dict[str, Any]]:
    coords = repository.parse_loc(loc)
    if not coords:
        return None
    lat, lon = coords
    return {
        "lat": lat,
        "lon": lon,
        "country": _clean_text(country),
        "region": _clean_text(region),
        "city": _clean_text(city),
        "org": _clean_text(org),
        "asn": _clean_text(asn),
        "asn_org": _clean_text(asn_org),
    }


def _role_for_direction(direction: str) -> Optional[str]:
    if direction == "outbound":
        return "destination"
    if direction == "inbound":
        return "source"
    return None


def _aggregate_threat_points(
    sources: list[dict[str, Any]],
    geo_by_ip: dict[str, dict[str, Any]],
    rules_by_ip: dict[str, list[tuple[str, int]]],
    classification_by_ip: dict[str, dict[str, Any]],
    *,
    limit: int,
) -> list[ThreatGeoPoint]:
    buckets: dict[tuple[float, float], dict[str, Any]] = {}
    for row in sources:
        ip = str(row["src_ip"] or "").strip()
        geo = geo_by_ip.get(ip)
        if not ip or not geo:
            continue
        lat = geo["lat"]
        lon = geo["lon"]
        key = (round(lat, CLUSTER_PRECISION), round(lon, CLUSTER_PRECISION))
        bucket = buckets.get(key)
        if bucket is None:
            bucket = buckets[key] = {
                "lat_weighted": 0.0,
                "lon_weighted": 0.0,
                "weight": 0,
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "alert_count": 0,
                "event_count": 0,
                "inbound_count": 0,
                "outbound_count": 0,
                "last_seen": None,
                "country": Counter(),
                "region": Counter(),
                "city": Counter(),
                "org": Counter(),
                "asn_org": Counter(),
                "ips": {},
                "rules": Counter(),
            }
        count = int(row.get("count", 0) or 0)
        critical = int(row.get("critical", 0) or 0)
        high = int(row.get("high", 0) or 0)
        medium = int(row.get("medium", 0) or 0)
        low = int(row.get("low", 0) or 0)
        weight = max(count, 1)
        provenance = str(row.get("provenance") or "alert")
        direction = str(row.get("direction") or "inbound")

        bucket["count"] += count
        bucket["critical"] += critical
        bucket["high"] += high
        bucket["medium"] += medium
        bucket["low"] += low
        bucket["lat_weighted"] += lat * weight
        bucket["lon_weighted"] += lon * weight
        bucket["weight"] += weight
        if provenance == "alert":
            bucket["alert_count"] += count
        else:
            bucket["event_count"] += count
        if direction == "outbound":
            bucket["outbound_count"] += count
        else:
            bucket["inbound_count"] += count

        last_seen = row.get("last_seen")
        if last_seen is not None and (bucket["last_seen"] is None or last_seen > bucket["last_seen"]):
            bucket["last_seen"] = last_seen

        for field in ("country", "region", "city", "org", "asn_org"):
            value = _clean_text(geo.get(field))
            if value:
                bucket[field][value] += weight

        classification = classification_by_ip.get(ip, {})
        ip_entry = bucket["ips"].get(ip)
        if ip_entry is None:
            ip_entry = bucket["ips"][ip] = {
                "ip": ip,
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "scope": classification.get("scope"),
                "label": classification.get("label"),
                "is_public": classification.get("is_public"),
                "asn": geo.get("asn"),
                "asn_org": geo.get("asn_org"),
                "org": geo.get("org"),
                "provenance": set(),
                "role": None,
            }
        ip_entry["count"] += count
        ip_entry["critical"] += critical
        ip_entry["high"] += high
        ip_entry["medium"] += medium
        ip_entry["low"] += low
        ip_entry["provenance"].add(provenance)
        if ip_entry["role"] is None:
            ip_entry["role"] = _role_for_direction(direction)
        for rule_id, rule_count in rules_by_ip.get(ip, []):
            bucket["rules"][rule_id] += rule_count

    points: list[ThreatGeoPoint] = []
    for bucket in buckets.values():
        weight = bucket["weight"] or 1
        ips_sorted = sorted(
            (
                ThreatGeoIp(
                    ip=entry["ip"],
                    count=entry["count"],
                    severity=_worst_severity(entry["critical"], entry["high"], entry["medium"], entry["low"]),
                    scope=entry["scope"],
                    label=entry["label"],
                    is_public=entry["is_public"],
                    asn=entry["asn"],
                    asn_org=entry["asn_org"],
                    org=entry["org"],
                    provenance="alert" if "alert" in entry["provenance"] else "event",
                    role=entry["role"],
                )
                for entry in bucket["ips"].values()
            ),
            key=lambda item: item.count,
            reverse=True,
        )
        provenance = (
            "mixed"
            if bucket["alert_count"] > 0 and bucket["event_count"] > 0
            else ("alert" if bucket["alert_count"] > 0 else "event")
        )
        direction = (
            "mixed"
            if bucket["inbound_count"] > 0 and bucket["outbound_count"] > 0
            else ("outbound" if bucket["outbound_count"] > 0 else "inbound")
        )
        points.append(
            ThreatGeoPoint(
                lat=round(bucket["lat_weighted"] / weight, 4),
                lon=round(bucket["lon_weighted"] / weight, 4),
                country=_mode(bucket["country"]),
                region=_mode(bucket["region"]),
                city=_mode(bucket["city"]),
                org=_mode(bucket["org"]),
                asn_org=_mode(bucket["asn_org"]),
                count=bucket["count"],
                critical=bucket["critical"],
                high=bucket["high"],
                medium=bucket["medium"],
                low=bucket["low"],
                severity=_worst_severity(bucket["critical"], bucket["high"], bucket["medium"], bucket["low"]),
                unique_ips=len(bucket["ips"]),
                last_seen=bucket["last_seen"],
                top_ips=ips_sorted[:TOP_IPS_PER_POINT],
                top_rules=[
                    ThreatGeoRuleCount(rule_id=rule_id, count=rule_count)
                    for rule_id, rule_count in bucket["rules"].most_common(TOP_RULES_PER_POINT)
                ],
                provenance=provenance,
                direction=direction,
                alert_count=bucket["alert_count"],
                event_count=bucket["event_count"],
            )
        )

    points.sort(key=lambda point: point.count, reverse=True)
    return points[: max(1, int(limit))]


def _flow_direction(src_cls: dict[str, Any] | None, dst_cls: dict[str, Any] | None) -> str:
    src_public = bool(src_cls and src_cls.get("is_public"))
    dst_public = bool(dst_cls and dst_cls.get("is_public"))
    src_internal = bool(src_cls and src_cls.get("is_internal"))
    dst_internal = bool(dst_cls and dst_cls.get("is_internal"))
    if src_public and dst_internal:
        return "inbound"
    if src_internal and dst_public:
        return "outbound"
    if src_internal and dst_internal:
        return "internal"
    return "transit"


def _endpoint(geo: dict[str, Any], classification: dict[str, Any] | None) -> ThreatGeoEndpoint:
    return ThreatGeoEndpoint(
        lat=geo["lat"],
        lon=geo["lon"],
        country=_clean_text(geo.get("country")),
        region=_clean_text(geo.get("region")),
        city=_clean_text(geo.get("city")),
        label=_location_label(geo.get("city"), geo.get("region"), geo.get("country")),
        scope=(classification or {}).get("scope"),
    )


def _build_flows(
    db: Session,
    *,
    event_rows: list[Any],
    alert_rows: list[Any],
    geo_by_ip: dict[str, dict[str, Any]],
    classification_by_ip: dict[str, dict[str, Any]],
    limit: int,
) -> list[ThreatGeoFlow]:
    flow_geo = dict(geo_by_ip)
    endpoint_ips: set[str] = set()

    def _register(ip: str) -> None:
        if ip and ip not in classification_by_ip:
            classification = classify_ip(ip)
            classification_by_ip[ip] = {
                "scope": classification["scope"],
                "label": classification["label"],
                "is_public": classification["is_public"],
                "is_internal": classification["is_internal"],
            }

    pairs: list[dict[str, Any]] = []
    for row in event_rows:
        src_ip = str(row.get("src_ip") or "").strip()
        dst_ip = str(row.get("dst_ip") or "").strip()
        if not src_ip or not dst_ip or src_ip == dst_ip:
            continue
        if src_ip not in flow_geo:
            rec = _extra_geo_record(
                loc=row.get("src_geo_loc"),
                country=row.get("src_country"),
                region=row.get("src_region"),
                city=row.get("src_city"),
            )
            if rec:
                flow_geo[src_ip] = rec
        endpoint_ips.update((src_ip, dst_ip))
        _register(src_ip)
        _register(dst_ip)
        high = int(row.get("high", 0) or 0)
        medium = int(row.get("medium", 0) or 0)
        pairs.append(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "count": int(row.get("count", 0) or 0),
                "severity": _worst_severity(0, high, medium, 0),
                "last_seen": row.get("last_seen"),
                "provenance": "event",
            }
        )
    for row in alert_rows:
        src_ip = str(row.get("src_ip") or "").strip()
        dst_ip = str(row.get("dst_ip") or "").strip()
        if not src_ip or not dst_ip or src_ip == dst_ip:
            continue
        endpoint_ips.update((src_ip, dst_ip))
        _register(src_ip)
        _register(dst_ip)
        critical = int(row.get("critical", 0) or 0)
        high = int(row.get("high", 0) or 0)
        medium = int(row.get("medium", 0) or 0)
        low = int(row.get("low", 0) or 0)
        pairs.append(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "count": int(row.get("count", 0) or 0),
                "severity": _worst_severity(critical, high, medium, low),
                "last_seen": row.get("last_seen"),
                "provenance": "alert",
            }
        )

    missing_public = sorted(
        ip
        for ip in endpoint_ips
        if ip not in flow_geo and classification_by_ip.get(ip, {}).get("is_public")
    )
    if missing_public:
        flow_geo.update(repository.load_geo_cache(db, missing_public))

    flows: list[ThreatGeoFlow] = []
    for pair in pairs:
        src_geo = flow_geo.get(pair["src_ip"])
        dst_geo = flow_geo.get(pair["dst_ip"])
        if not src_geo or not dst_geo:
            continue
        src_cls = classification_by_ip.get(pair["src_ip"])
        dst_cls = classification_by_ip.get(pair["dst_ip"])
        flows.append(
            ThreatGeoFlow(
                id=f"{pair['provenance'][0]}:{pair['src_ip']}->{pair['dst_ip']}",
                origin=_endpoint(src_geo, src_cls),
                target=_endpoint(dst_geo, dst_cls),
                direction=_flow_direction(src_cls, dst_cls),
                provenance=pair["provenance"],
                severity=pair["severity"],
                weight=pair["count"],
                count=pair["count"],
                last_seen=pair["last_seen"],
            )
        )

    flows.sort(key=lambda flow: (flow.provenance != "alert", -flow.weight))
    return flows[: max(0, int(limit))]


def _build_rankings(
    sources: list[dict[str, Any]],
    geo_by_ip: dict[str, dict[str, Any]],
    classification_by_ip: dict[str, dict[str, Any]],
) -> dict[str, list[Any]]:
    src_ip_acc: dict[str, dict[str, Any]] = {}
    dst_ip_acc: dict[str, dict[str, Any]] = {}
    src_country_acc: dict[str, dict[str, Any]] = {}
    dst_country_acc: dict[str, dict[str, Any]] = {}

    for row in sources:
        ip = str(row["src_ip"]).strip()
        geo = geo_by_ip.get(ip)
        if not geo:
            continue
        outbound = row.get("direction") == "outbound"
        ip_acc = dst_ip_acc if outbound else src_ip_acc
        country_acc = dst_country_acc if outbound else src_country_acc
        count = int(row.get("count", 0) or 0)
        critical = int(row.get("critical", 0) or 0)
        high = int(row.get("high", 0) or 0)
        medium = int(row.get("medium", 0) or 0)
        low = int(row.get("low", 0) or 0)
        provenance = str(row.get("provenance") or "event")

        entry = ip_acc.get(ip)
        if entry is None:
            classification = classification_by_ip.get(ip, {})
            entry = ip_acc[ip] = {
                "ip": ip,
                "count": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "country": _clean_text(geo.get("country")),
                "org": _clean_text(geo.get("org")),
                "asn_org": _clean_text(geo.get("asn_org")),
                "scope": classification.get("scope"),
                "label": classification.get("label"),
                "is_public": classification.get("is_public"),
                "provenance": set(),
                "role": "destination" if outbound else "source",
            }
        entry["count"] += count
        entry["critical"] += critical
        entry["high"] += high
        entry["medium"] += medium
        entry["low"] += low
        entry["provenance"].add(provenance)

        country = _clean_text(geo.get("country"))
        if country:
            cacc = country_acc.get(country)
            if cacc is None:
                cacc = country_acc[country] = {
                    "country": country,
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "ips": set(),
                    "provenance": set(),
                }
            cacc["count"] += count
            cacc["critical"] += critical
            cacc["high"] += high
            cacc["medium"] += medium
            cacc["low"] += low
            cacc["ips"].add(ip)
            cacc["provenance"].add(provenance)

    def _rank_ips(acc: dict[str, dict[str, Any]]) -> list[ThreatGeoRankIp]:
        ranked = sorted(acc.values(), key=lambda item: item["count"], reverse=True)[:TOP_RANK]
        return [
            ThreatGeoRankIp(
                ip=item["ip"],
                count=item["count"],
                severity=_worst_severity(item["critical"], item["high"], item["medium"], item["low"]),
                country=item["country"],
                org=item["org"],
                asn_org=item["asn_org"],
                scope=item["scope"],
                label=item["label"],
                is_public=item["is_public"],
                provenance="alert" if "alert" in item["provenance"] else "event",
                role=item["role"],
            )
            for item in ranked
        ]

    def _rank_countries(acc: dict[str, dict[str, Any]]) -> list[ThreatGeoRankCountry]:
        ranked = sorted(acc.values(), key=lambda item: item["count"], reverse=True)[:TOP_RANK]
        return [
            ThreatGeoRankCountry(
                country=item["country"],
                count=item["count"],
                unique_ips=len(item["ips"]),
                severity=_worst_severity(item["critical"], item["high"], item["medium"], item["low"]),
                provenance="alert" if "alert" in item["provenance"] else "event",
            )
            for item in ranked
        ]

    return {
        "top_source_ips": _rank_ips(src_ip_acc),
        "top_destination_ips": _rank_ips(dst_ip_acc),
        "top_source_countries": _rank_countries(src_country_acc),
        "top_destination_countries": _rank_countries(dst_country_acc),
    }


def get_threat_geo(
    db: Session,
    *,
    since_minutes: int = 60 * 24,
    limit: int = 200,
    severity: Optional[str] = None,
    source: str = "both",
) -> ThreatGeoResponse:
    started = time.perf_counter()
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(minutes=int(since_minutes))
    since = datetime.utcnow() - timedelta(minutes=int(since_minutes))
    sev = (severity or "").strip().lower() or None
    src_mode = (source or "both").strip().lower()
    if src_mode not in VALID_SOURCES:
        src_mode = "both"
    want_alerts = src_mode in ("alerts", "both")
    want_events = src_mode in ("events", "both")

    cache_key = (
        f"seagull:threat_map:geo:v2:sm={int(since_minutes)}:l={int(limit)}"
        f":sev={sev or '*'}:src={src_mode}"
    )
    cached = _cache_get_json(cache_key)
    if isinstance(cached, dict) and isinstance(cached.get("meta"), dict) and str(cached["meta"].get("source") or "").strip():
        out = dict(cached)
        meta = dict(out["meta"])
        meta["cache_hit"] = True
        meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
        out["meta"] = meta
        return ThreatGeoResponse(**out)

    sources: list[dict[str, Any]] = []
    extra_geo_by_ip: dict[str, dict[str, Any]] = {}

    if want_alerts:
        sources.extend(
            _normalize_source_rows(
                repository.aggregate_threat_sources(db, since=since, severity=sev),
                provenance="alert",
                direction="inbound",
            )
        )
    if want_events:
        event_source_rows = repository.aggregate_event_sources(db, since=since, severity=sev)
        for row in event_source_rows:
            ip = str(row.get("src_ip") or "").strip()
            if not ip:
                continue
            rec = _extra_geo_record(
                loc=row.get("geo_loc"),
                country=row.get("country"),
                region=row.get("region"),
                city=row.get("city"),
                org=row.get("org"),
                asn=row.get("asn"),
                asn_org=row.get("asn_org"),
            )
            if rec:
                extra_geo_by_ip[ip] = rec
        sources.extend(_normalize_source_rows(event_source_rows, provenance="event", direction="inbound"))
        sources.extend(
            _normalize_source_rows(
                repository.aggregate_event_destinations(db, since=since, severity=sev),
                provenance="event",
                direction="outbound",
            )
        )
        sources.extend(
            _normalize_source_rows(
                _expand_dos_sources(repository.recent_dos_attack_events(db, since=since, severity=sev)),
                provenance="event",
                direction="inbound",
            )
        )

    classification_by_ip: dict[str, dict[str, Any]] = {}
    public_ips: list[str] = []
    for row in sources:
        ip = str(row["src_ip"] or "").strip()
        if not ip or ip in classification_by_ip:
            continue
        classification = classify_ip(ip)
        classification_by_ip[ip] = {
            "scope": classification["scope"],
            "label": classification["label"],
            "is_public": classification["is_public"],
            "is_internal": classification["is_internal"],
        }
        if classification["is_public"]:
            public_ips.append(ip)

    geo_by_ip: dict[str, dict[str, Any]] = {
        ip: rec for ip, rec in extra_geo_by_ip.items() if ip in classification_by_ip and classification_by_ip[ip]["is_public"]
    }
    missing_public = [ip for ip in public_ips if ip not in geo_by_ip]
    if missing_public:
        geo_by_ip.update(repository.load_geo_cache(db, missing_public))

    located = set(geo_by_ip.keys())
    located_sources = [row for row in sources if str(row["src_ip"] or "").strip() in located]

    rules_by_ip: dict[str, list[tuple[str, int]]] = {}
    alert_located = sorted(
        {row["src_ip"] for row in located_sources if row["provenance"] == "alert"}
    )
    if want_alerts and alert_located:
        for row in repository.aggregate_threat_source_rules(db, since=since, severity=sev, src_ips=alert_located):
            rule_id = str(row.get("rule_id") or "").strip()
            ip = str(row.get("src_ip") or "").strip()
            if rule_id and ip:
                rules_by_ip.setdefault(ip, []).append((rule_id, int(row.get("count", 0) or 0)))

    points = _aggregate_threat_points(
        located_sources,
        geo_by_ip,
        rules_by_ip,
        classification_by_ip,
        limit=int(limit),
    )

    flows: list[ThreatGeoFlow] = []
    if located:
        event_flow_rows = repository.aggregate_event_flows(db, since=since, severity=sev) if want_events else []
        alert_flow_rows = repository.aggregate_alert_flows(db, since=since, severity=sev) if want_alerts else []
        if event_flow_rows or alert_flow_rows:
            flows = _build_flows(
                db,
                event_rows=event_flow_rows,
                alert_rows=alert_flow_rows,
                geo_by_ip=geo_by_ip,
                classification_by_ip=classification_by_ip,
                limit=FLOW_LIMIT,
            )

    rankings = _build_rankings(located_sources, geo_by_ip, classification_by_ip)

    total_alerts = sum(row["count"] for row in located_sources if row["provenance"] == "alert")
    total_events = sum(row["count"] for row in located_sources if row["provenance"] == "event")

    payload = ThreatGeoResponse(
        generated_at=window_end,
        since_minutes=int(since_minutes),
        severity=sev,
        source=src_mode,
        home=_resolve_home_endpoint(),
        total_alerts=total_alerts,
        total_events=total_events,
        located_ips=len(located),
        unlocated_ips=max(0, len(public_ips) - len(located)),
        points=points,
        flows=flows,
        top_source_countries=rankings["top_source_countries"],
        top_destination_countries=rankings["top_destination_countries"],
        top_source_ips=rankings["top_source_ips"],
        top_destination_ips=rankings["top_destination_ips"],
        meta=ThreatGeoMeta(
            source="postgres",
            cache_hit=False,
            query_latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
            query_window_start=window_start,
            query_window_end=window_end,
        ),
    )
    _cache_set_json(
        cache_key,
        payload.dict(),
        int(getattr(settings, "SEAGULL_THREAT_GEO_CACHE_TTL_SECONDS", 30) or 30),
    )
    return payload
