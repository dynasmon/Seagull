from __future__ import annotations

import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.core.cache import get_json, set_json
from app.core.config import settings
from app.features.threat_map import repository
from app.features.threat_map.schemas import (
    ThreatGeoIp,
    ThreatGeoMeta,
    ThreatGeoPoint,
    ThreatGeoResponse,
    ThreatGeoRuleCount,
)
from app.shared.network.ip_classification import classify_ip

CLUSTER_PRECISION = 1
TOP_IPS_PER_POINT = 6
TOP_RULES_PER_POINT = 6


def _cache_get_json(key: str) -> dict[str, Any] | None:
    return get_json(key)


def _cache_set_json(key: str, payload: dict[str, Any], ttl_s: int) -> None:
    set_json(key, payload, ttl_s)


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


def _aggregate_threat_points(
    sources: list[Any],
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
                "last_seen": None,
                "country": Counter(),
                "region": Counter(),
                "city": Counter(),
                "org": Counter(),
                "asn_org": Counter(),
                "ips": [],
                "rules": Counter(),
            }
        count = int(row.get("count", 0) or 0)
        critical = int(row.get("critical", 0) or 0)
        high = int(row.get("high", 0) or 0)
        medium = int(row.get("medium", 0) or 0)
        low = int(row.get("low", 0) or 0)
        weight = max(count, 1)

        bucket["count"] += count
        bucket["critical"] += critical
        bucket["high"] += high
        bucket["medium"] += medium
        bucket["low"] += low
        bucket["lat_weighted"] += lat * weight
        bucket["lon_weighted"] += lon * weight
        bucket["weight"] += weight

        last_seen = row.get("last_seen")
        if last_seen is not None and (bucket["last_seen"] is None or last_seen > bucket["last_seen"]):
            bucket["last_seen"] = last_seen

        for field in ("country", "region", "city", "org", "asn_org"):
            value = geo.get(field)
            if isinstance(value, str):
                value = value.strip()
            if value:
                bucket[field][value] += weight

        classification = classification_by_ip.get(ip, {})
        bucket["ips"].append(
            ThreatGeoIp(
                ip=ip,
                count=count,
                severity=_worst_severity(critical, high, medium, low),
                scope=classification.get("scope"),
                label=classification.get("label"),
                is_public=classification.get("is_public"),
                asn=geo.get("asn"),
                asn_org=geo.get("asn_org"),
                org=geo.get("org"),
            )
        )
        for rule_id, rule_count in rules_by_ip.get(ip, []):
            bucket["rules"][rule_id] += rule_count

    points: list[ThreatGeoPoint] = []
    for bucket in buckets.values():
        weight = bucket["weight"] or 1
        ips_sorted = sorted(bucket["ips"], key=lambda item: item.count, reverse=True)
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
            )
        )

    points.sort(key=lambda point: point.count, reverse=True)
    return points[: max(1, int(limit))]


def get_threat_geo(
    db: Session,
    *,
    since_minutes: int = 60 * 24,
    limit: int = 200,
    severity: Optional[str] = None,
) -> ThreatGeoResponse:
    started = time.perf_counter()
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(minutes=int(since_minutes))
    since = datetime.utcnow() - timedelta(minutes=int(since_minutes))
    sev = (severity or "").strip().lower() or None

    cache_key = f"seagull:threat_map:geo:v1:sm={int(since_minutes)}:l={int(limit)}:sev={sev or '*'}"
    cached = _cache_get_json(cache_key)
    if isinstance(cached, dict) and isinstance(cached.get("meta"), dict) and str(cached["meta"].get("source") or "").strip():
        out = dict(cached)
        meta = dict(out["meta"])
        meta["cache_hit"] = True
        meta["query_latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
        out["meta"] = meta
        return ThreatGeoResponse(**out)

    sources = repository.aggregate_threat_sources(db, since=since, severity=sev)

    classification_by_ip: dict[str, dict[str, Any]] = {}
    public_ips: list[str] = []
    for row in sources:
        ip = str(row["src_ip"] or "").strip()
        if not ip:
            continue
        classification = classify_ip(ip)
        classification_by_ip[ip] = {
            "scope": classification["scope"],
            "label": classification["label"],
            "is_public": classification["is_public"],
        }
        if classification["is_public"]:
            public_ips.append(ip)

    geo_by_ip = repository.load_geo_cache(db, public_ips)
    located = set(geo_by_ip.keys())
    located_sources = [row for row in sources if str(row["src_ip"] or "").strip() in located]

    rules_by_ip: dict[str, list[tuple[str, int]]] = {}
    if located:
        for row in repository.aggregate_threat_source_rules(db, since=since, severity=sev, src_ips=sorted(located)):
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

    payload = ThreatGeoResponse(
        generated_at=window_end,
        since_minutes=int(since_minutes),
        severity=sev,
        total_alerts=sum(int(row.get("count", 0) or 0) for row in located_sources),
        located_ips=len(located),
        unlocated_ips=max(0, len(public_ips) - len(located)),
        points=points,
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
