"""Lupe enrichment worker.

Enriches SSH auth events (event_type='ssh_auth') with Geo/ASN metadata from ipinfo.io.

This worker is intentionally self-contained (stdlib HTTP) to keep the foundation stack light.

Writes into net_events.extra (only when missing):
- geo_country, geo_region, geo_city, geo_loc
- geo_org
- asn, asn_org
- lupe_enriched_at (RFC3339 UTC)

Cache:
- ip_enrichment_cache (Postgres) to avoid repeated calls + respect ipinfo rate limits.
"""

from __future__ import annotations

import ipaddress
import json
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

from app.core.db import Base, engine
from app.core.schema_bootstrap import bootstrap_schema
from app.models.events import NetEventModel
from app.models.ip_enrichment_cache import IpEnrichmentCacheModel
from app.models.search_index_offsets import SearchIndexOffsetModel


OFFSET_LUPE = "lupe_enricher_ssh_v1"

# Only enrich these actions (accepted, failed_password, invalid_user). This matches the Lupe intent.
SSH_ACTIONS: tuple[str, ...] = ("accepted", "failed_password", "invalid_user")

ASN_RE = re.compile(r"^(AS\d+)\s+(.*)$")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if raw == "":
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    # Skip private, loopback, link-local, multicast, unspecified, reserved.
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


def _ensure_bootstrap(default_ttl_days: int) -> None:
    """Self-healing bootstrap.

    The backend runs schema_bootstrap at startup, but workers may start first.
    """
    Base.metadata.create_all(bind=engine)
    bootstrap_schema(engine)
    with engine.begin() as conn:
        conn.execute(
            insert(SearchIndexOffsetModel)
            .values(name=OFFSET_LUPE, last_id=0)
            .on_conflict_do_nothing(index_elements=[SearchIndexOffsetModel.name])
        )
        # Keep default TTL consistent even if older rows have NULL.
        conn.execute(
            update(IpEnrichmentCacheModel)
            .where(IpEnrichmentCacheModel.expires_at.is_(None))
            .values(expires_at=_utc_now() + timedelta(days=int(default_ttl_days)))
        )


def _get_last_id() -> int:
    with engine.begin() as conn:
        row = conn.execute(
            select(SearchIndexOffsetModel.last_id).where(SearchIndexOffsetModel.name == OFFSET_LUPE).limit(1),
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0


def _set_last_id(last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            insert(SearchIndexOffsetModel)
            .values(name=OFFSET_LUPE, last_id=int(last_id))
            .on_conflict_do_update(
                index_elements=[SearchIndexOffsetModel.name],
                set_={"last_id": int(last_id), "updated_at": func.now()},
            )
        )


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
            # SQLAlchemy returns aware datetimes for timestamptz
            try:
                if expires_at <= _utc_now():
                    return None
            except Exception:
                return None
        # Build a normalized record
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


def _build_record(ipinfo: dict) -> dict:
    country = ipinfo.get("country")
    region = ipinfo.get("region")
    city = ipinfo.get("city")
    loc = ipinfo.get("loc")
    org = ipinfo.get("org")
    asn, asn_org = _parse_asn(org)

    # Cache keeps the whole payload for debugging, but events only store the curated subset.
    return {
        "country": country,
        "region": region,
        "city": city,
        "loc": loc,
        "org": org,
        "asn": asn,
        "asn_org": asn_org,
        "data": ipinfo,
    }


def _patch_event(event_id: int, patch: dict) -> None:
    with engine.begin() as conn:
        conn.execute(
            update(NetEventModel)
            .where(NetEventModel.id == int(event_id))
            .values(extra=NetEventModel.extra.op("||")(patch))
        )


def main() -> None:
    token = (os.getenv("NETWATCH_IPINFO_TOKEN") or "").strip()

    every_s = _env_float("NETWATCH_LUPE_EVERY_SECONDS", 1.0)
    idle_sleep_s = _env_float("NETWATCH_LUPE_IDLE_SLEEP_SECONDS", 2.0)
    max_rows = _env_int("NETWATCH_LUPE_MAX_ROWS", 2000)
    batch_size = _env_int("NETWATCH_LUPE_BATCH_SIZE", 200)
    timeout_s = _env_float("NETWATCH_LUPE_HTTP_TIMEOUT_SECONDS", 8.0)
    cache_ttl_days = _env_int("NETWATCH_LUPE_CACHE_TTL_DAYS", 7)
    skip_private = (os.getenv("NETWATCH_LUPE_SKIP_PRIVATE", "true").strip().lower() != "false")

    backoff = 1.0

    while True:
        try:
            _ensure_bootstrap(cache_ttl_days)

            if not token:
                # Keep the worker alive but do no work.
                print("[LUPE] NETWATCH_IPINFO_TOKEN is empty; waiting")
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
                # No unenriched ssh_auth in this range; advance offset to avoid rescans.
                _set_last_id(max_id)
                time.sleep(max(every_s, 0.1))
                backoff = 1.0
                continue

            last_done_id = last_id
            t0 = time.time()

            for r in rows:
                eid = int(r["id"])
                ip = (r.get("src_ip") or "").strip()

                # Always stamp lupe_enriched_at to make progress monotonic.
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
                    try:
                        ipinfo = _fetch_ipinfo(ip, token, timeout_s)
                    except HTTPError as e:
                        # Typical: 429 rate-limit, 401 invalid token.
                        raise RuntimeError(f"ipinfo_http_error status={getattr(e, 'code', None)}") from e
                    except URLError as e:
                        raise RuntimeError("ipinfo_network_error") from e
                    rec = _build_record(ipinfo)
                    _upsert_cache(ip, rec, cache_ttl_days)
                    cached = rec

                patch = {
                    **base_patch,
                    "geo_country": cached.get("country"),
                    "geo_region": cached.get("region"),
                    "geo_city": cached.get("city"),
                    "geo_loc": cached.get("loc"),
                    "geo_org": cached.get("org"),
                    "asn": cached.get("asn"),
                    "asn_org": cached.get("asn_org"),
                }
                patch = _compact(patch)

                _patch_event(eid, patch)
                last_done_id = eid

            _set_last_id(last_done_id)
            took_ms = int((time.time() - t0) * 1000)
            print(f"[LUPE] ok last_id={last_id} max_id={max_id} processed={len(rows)} took_ms={took_ms}")

            backoff = 1.0
            time.sleep(max(every_s, 0.1))

        except OperationalError as e:
            wait_s = min(backoff, 15.0)
            print(f"[LUPE] db_not_ready wait_s={wait_s} error={str(e).splitlines()[0]}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 15.0)
        except Exception as e:
            wait_s = min(backoff, 30.0)
            print(f"[LUPE] error wait_s={wait_s} error={repr(e)}")
            time.sleep(wait_s)
            backoff = min(backoff * 2.0, 30.0)


if __name__ == "__main__":
    main()
