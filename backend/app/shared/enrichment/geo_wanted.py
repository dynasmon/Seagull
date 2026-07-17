from __future__ import annotations

from typing import Iterable

from app.core.cache import get_redis

WANTED_KEY = "seagull:threat_map:geo:wanted:v1"
WANTED_MAX_MEMBERS = 512
WANTED_TTL_SECONDS = 4 * 3600


def push_wanted_ips(entries: Iterable[tuple[str, int]]) -> None:
    mapping: dict[str, float] = {}
    for ip, weight in entries:
        value = str(ip or "").strip()
        if value:
            mapping[value] = max(float(weight or 0), mapping.get(value, 0.0))
    if not mapping:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.zadd(WANTED_KEY, mapping)
        r.zremrangebyrank(WANTED_KEY, 0, -(WANTED_MAX_MEMBERS + 1))
        r.expire(WANTED_KEY, WANTED_TTL_SECONDS)
    except Exception:
        return


def pull_wanted_ips(limit: int) -> list[str]:
    if limit <= 0:
        return []
    r = get_redis()
    if r is None:
        return []
    try:
        members = r.zrevrange(WANTED_KEY, 0, int(limit) - 1)
    except Exception:
        return []
    return [str(member).strip() for member in (members or []) if str(member).strip()]


def discard_wanted_ips(ips: Iterable[str]) -> None:
    values = [str(ip).strip() for ip in ips if str(ip).strip()]
    if not values:
        return
    r = get_redis()
    if r is None:
        return
    try:
        r.zrem(WANTED_KEY, *values)
    except Exception:
        return
