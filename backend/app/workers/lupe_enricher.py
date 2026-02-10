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

from sqlalchemy import bindparam, text
from sqlalchemy.exc import OperationalError

from app.core.db import engine


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
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS search_index_offsets (
                    name TEXT PRIMARY KEY,
                    last_id INTEGER NOT NULL DEFAULT 0,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS ip_enrichment_cache (
                    ip VARCHAR(45) PRIMARY KEY,
                    country VARCHAR(8) NULL,
                    region VARCHAR(128) NULL,
                    city VARCHAR(128) NULL,
                    loc VARCHAR(32) NULL,
                    org VARCHAR(256) NULL,
                    asn VARCHAR(32) NULL,
                    asn_org VARCHAR(256) NULL,
                    data JSONB NOT NULL DEFAULT '{}'::jsonb,
                    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days')
                );
                """
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_ip_enrichment_cache_expires_at ON ip_enrichment_cache (expires_at);"))

        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets (name, last_id)
                VALUES (:n, 0)
                ON CONFLICT (name) DO NOTHING;
                """
            ),
            {"n": OFFSET_LUPE},
        )

        # Keep default TTL consistent even if bootstrap created older defaults.
        conn.execute(
            text(
                """
                UPDATE ip_enrichment_cache
                SET expires_at = GREATEST(expires_at, now() + (:ttl_days || ' days')::interval)
                WHERE expires_at IS NULL;
                """
            ),
            {"ttl_days": int(default_ttl_days)},
        )


def _get_last_id() -> int:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT last_id FROM search_index_offsets WHERE name=:name"),
            {"name": OFFSET_LUPE},
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0


def _set_last_id(last_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO search_index_offsets(name, last_id)
                VALUES (:name, :last_id)
                ON CONFLICT (name) DO UPDATE
                  SET last_id = EXCLUDED.last_id,
                      updated_at = now();
                """
            ),
            {"name": OFFSET_LUPE, "last_id": int(last_id)},
        )


def _pick_batch_max_id(last_id: int, max_rows: int) -> Optional[int]:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT MAX(id) FROM (
                    SELECT id
                    FROM net_events
                    WHERE id > :last_id
                    ORDER BY id
                    LIMIT :max_rows
                ) t;
                """
            ),
            {"last_id": int(last_id), "max_rows": int(max_rows)},
        ).fetchone()
        v = row[0] if row else None
        return int(v) if v is not None else None


def _fetch_batch(last_id: int, max_id: int, limit: int) -> list[dict]:
    with engine.begin() as conn:
        stmt = text(
            """
            SELECT id, agent_id, src_ip, extra->>'action' AS action
            FROM net_events
            WHERE id > :last_id AND id <= :max_id
              AND event_type = 'ssh_auth'
              AND src_ip IS NOT NULL
              AND (extra->>'action') IN :actions
              AND NOT (extra ? 'lupe_enriched_at')
            ORDER BY id
            LIMIT :limit;
            """
        ).bindparams(bindparam("actions", expanding=True))

        rows = conn.execute(
            stmt,
            {"last_id": int(last_id), "max_id": int(max_id), "actions": list(SSH_ACTIONS), "limit": int(limit)},
        ).mappings().all()
        return [dict(r) for r in rows]


def _get_cached_ip(ip: str) -> Optional[dict]:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT country, region, city, loc, org, asn, asn_org, data, expires_at
                FROM ip_enrichment_cache
                WHERE ip = :ip;
                """
            ),
            {"ip": ip},
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
        conn.execute(
            text(
                """
                INSERT INTO ip_enrichment_cache (
                    ip, country, region, city, loc, org, asn, asn_org, data, fetched_at, expires_at
                ) VALUES (
                    :ip, :country, :region, :city, :loc, :org, :asn, :asn_org, CAST(:data AS jsonb), now(), :expires_at
                )
                ON CONFLICT (ip) DO UPDATE SET
                    country = EXCLUDED.country,
                    region = EXCLUDED.region,
                    city = EXCLUDED.city,
                    loc = EXCLUDED.loc,
                    org = EXCLUDED.org,
                    asn = EXCLUDED.asn,
                    asn_org = EXCLUDED.asn_org,
                    data = EXCLUDED.data,
                    fetched_at = now(),
                    expires_at = EXCLUDED.expires_at;
                """
            ),
            {
                "ip": ip,
                "country": rec.get("country"),
                "region": rec.get("region"),
                "city": rec.get("city"),
                "loc": rec.get("loc"),
                "org": rec.get("org"),
                "asn": rec.get("asn"),
                "asn_org": rec.get("asn_org"),
                "data": json.dumps(rec.get("data") or {}, separators=(",", ":")),
                "expires_at": expires_at,
            },
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
            text(
                """
                UPDATE net_events
                SET extra = extra || CAST(:patch AS jsonb)
                WHERE id = :id;
                """
            ),
            {"id": int(event_id), "patch": json.dumps(patch, separators=(",", ":"))},
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
