from datetime import datetime, timezone
from typing import Any, Dict, Optional

from zoneinfo import ZoneInfo


def _schedule_allows(rule: Dict[str, Any], now_utc: datetime) -> bool:
    schedule = rule.get("schedule")
    if not isinstance(schedule, dict) or not schedule.get("enabled"):
        return True

    tz_name = (schedule.get("timezone") or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc

    local = now_utc.replace(tzinfo=timezone.utc).astimezone(tz)

    # Day allowlist
    days = schedule.get("days") or schedule.get("weekdays") or []
    if isinstance(days, str):
        days = [days]
    allow = []
    for d in (days or []):
        s = str(d).strip().lower()[:3]
        if s:
            allow.append(s)
    if allow:
        wd = local.strftime("%a").strip().lower()[:3]
        if wd not in set(allow):
            return False

    def _hhmm_to_min(s: str) -> Optional[int]:
        s = str(s or "").strip()
        if not s or ":" not in s:
            return None
        hh, mm = s.split(":", 1)
        try:
            h = int(hh)
            m = int(mm)
        except Exception:
            return None
        if h < 0 or h > 23 or m < 0 or m > 59:
            return None
        return h * 60 + m

    start_m = _hhmm_to_min(schedule.get("start") or "00:00")
    end_m = _hhmm_to_min(schedule.get("end") or "23:59")
    if start_m is None or end_m is None:
        return True

    now_m = local.hour * 60 + local.minute

    # Same start/end => always on
    if start_m == end_m:
        return True

    # Non-wrapping window
    if start_m < end_m:
        return start_m <= now_m <= end_m

    # Wrapping (crosses midnight)
    return now_m >= start_m or now_m <= end_m


def _parse_iso_utc(raw: Any) -> Optional[datetime]:
    s = str(raw or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _suppression_matches(sup: Dict[str, Any], ctx: Dict[str, Any], now_utc: datetime) -> bool:
    until = _parse_iso_utc(sup.get("until"))
    if until is not None and now_utc.replace(tzinfo=timezone.utc) > until:
        return False

    when = sup.get("when")
    if not isinstance(when, dict) or not when:
        return True

    for k, expected in when.items():
        actual = ctx.get(str(k))
        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False
    return True


def _is_suppressed(rule: Dict[str, Any], ctx: Dict[str, Any], now_utc: datetime) -> tuple[bool, Optional[str]]:
    sups = rule.get("suppressions")
    if not isinstance(sups, list) or not sups:
        return False, None

    for sup in sups:
        if not isinstance(sup, dict):
            continue
        if _suppression_matches(sup, ctx, now_utc):
            return True, str(sup.get("reason") or "suppressed")
    return False, None
