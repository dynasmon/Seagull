import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from zoneinfo import ZoneInfo

import yaml
from sqlalchemy import and_, cast, func, select, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import Float

from app.core.db import SessionLocal
from app.models.alerts import AlertModel
from app.models.events import NetEventModel
from app.workers.rules_registry import (
    apply_override,
    apply_tuning_and_suppressions,
    fetch_overrides,
    fetch_suppressions,
    fetch_tuning,
    load_baseline_rules,
    normalize_rule_list,
)

from app.mitre.catalog import technique_name

_ALLOWED_EVENT_FIELDS = {
    "agent_id",
    "event_type",
    "src_ip",
    "dst_ip",
    "dst_port",
    "src_port",
    "proto",
    "bytes",
}



def _clamp_int(v: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(v)
    except Exception:
        return int(default)
    return max(int(lo), min(int(hi), n))


def _extract_mitre_meta(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and normalize MITRE ATT&CK metadata from a rule dict.

    Expected schema in YAML:
        mitre:
          tactic: "discovery"
          technique_id: "T1046"
          technique: "Network Service Scanning"  # optional
          confidence: 75

    Returns an empty dict if no metadata is defined.
    """

    m = rule.get('mitre')
    if not isinstance(m, dict):
        return {}

    tactic = str(m.get('tactic') or '').strip() or None
    technique_id = str(m.get('technique_id') or m.get('technique') or '').strip() or None

    # If the YAML uses 'technique' as the name, keep it separate.
    technique = m.get('technique_name') if 'technique_name' in m else m.get('technique')
    technique = str(technique or '').strip() or None

    if technique_id and not technique:
        technique = technique_name(technique_id)

    confidence = _clamp_int(m.get('confidence', 50), 0, 100, 50)

    out: Dict[str, Any] = {}
    if tactic:
        out['tactic'] = tactic
    if technique_id:
        out['technique_id'] = technique_id
    if technique:
        out['technique'] = technique
    out['confidence'] = confidence

    return out

def _safe_col(field: str):
    if field not in _ALLOWED_EVENT_FIELDS:
        raise ValueError(f"Invalid field: {field}")
    return getattr(NetEventModel, field)


def _evaluate_condition(value: int, condition: Dict) -> bool:
    op = (condition.get("operator") or ">=").strip()
    target = int(condition.get("value") or 0)

    if op == ">=":
        return value >= target
    if op == ">":
        return value > target
    if op == "<=":
        return value <= target
    if op == "<":
        return value < target
    if op == "==":
        return value == target
    if op == "!=":
        return value != target

    return value >= target


def _extract_alert_key(group_key: Dict, match: Dict) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    src_ip = group_key.get("src_ip") if "src_ip" in group_key else match.get("src_ip")
    dst_ip = group_key.get("dst_ip") if "dst_ip" in group_key else match.get("dst_ip")
    dst_port = group_key.get("dst_port") if "dst_port" in group_key else match.get("dst_port")

    if dst_port is not None:
        try:
            dst_port = int(dst_port)
        except Exception:
            dst_port = None

    return src_ip, dst_ip, dst_port


def _normalize_dedup_key(rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]):
    """Normalize dedup key so enrichment doesn't create duplicate alerts.

    - DDoS/DoS/L7 rules: dedup ignores src_ip (because alerts may be enriched with a representative attacker)
    - SSH bruteforce rules: dedup ignores dst_ip (because alerts may be enriched with the local/target IP)
    """
    rid = str(rule_id or "")
    src = src_ip
    dst = dst_ip

    if rid.startswith(("ddos_", "dos_", "l7_")):
        src = None
    if rid.startswith("ssh_bruteforce_"):
        dst = None

    return (rid, src, dst, int(dst_port) if dst_port is not None else None)


def _recent_alert_index(
    db: Session, horizon: timedelta
) -> Dict[Tuple[str, Optional[str], Optional[str], Optional[int]], datetime]:
    threshold = datetime.utcnow() - horizon

    stmt = (
        select(
            AlertModel.rule_id,
            AlertModel.src_ip,
            AlertModel.dst_ip,
            AlertModel.dst_port,
            func.max(AlertModel.created_at),
        )
        .where(AlertModel.created_at >= threshold)
        .group_by(AlertModel.rule_id, AlertModel.src_ip, AlertModel.dst_ip, AlertModel.dst_port)
    )

    rows = db.execute(stmt).all()
    idx: Dict[Tuple[str, Optional[str], Optional[str], Optional[int]], datetime] = {}
    for rule_id, src_ip, dst_ip, dst_port, last_at in rows:
        key = _normalize_dedup_key(rule_id, src_ip, dst_ip, dst_port)
        idx[key] = last_at

    return idx


def _recent_alert_last_at(
    idx: Dict, rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]
) -> Optional[datetime]:
    return idx.get(_normalize_dedup_key(rule_id, src_ip, dst_ip, dst_port))


def _recent_alert_exists_cached(
    idx: Dict, rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]
) -> bool:
    return _recent_alert_last_at(idx, rule_id, src_ip, dst_ip, dst_port) is not None


def _index_add(idx: Dict, rule_id: str, src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int]):
    idx[_normalize_dedup_key(rule_id, src_ip, dst_ip, dst_port)] = datetime.utcnow()


def _parse_extra_key(raw_key: str) -> Tuple[str, str]:
    k = raw_key[len("extra_") :]

    for suffix, op in (
        ("_not_in", "not_in"),
        ("_in", "in"),
        ("_gte", "gte"),
        ("_gt", "gt"),
        ("_lte", "lte"),
        ("_lt", "lt"),
        ("_neq", "neq"),
    ):
        if k.endswith(suffix):
            return k[: -len(suffix)], op

    return k, "eq"


def _extra_text_col(key: str):
    return NetEventModel.extra.op("->>")(key)


def _extra_numeric_col(key: str):
    txt = _extra_text_col(key)
    is_numeric = txt.op("~")("^-?[0-9]+(\\.[0-9]+)?$")
    num = cast(txt, Float)
    return is_numeric, num


def _build_match_filters(match: Dict, since: datetime, until: datetime) -> List:
    filters = [NetEventModel.timestamp >= since, NetEventModel.timestamp < until]

    def _parse_field_op(raw_key: str) -> Tuple[Optional[str], Optional[str]]:
        for suffix, op in (
            ("_not_in", "not_in"),
            ("_in", "in"),
            ("_gte", "gte"),
            ("_gt", "gt"),
            ("_lte", "lte"),
            ("_lt", "lt"),
            ("_neq", "neq"),
        ):
            if raw_key.endswith(suffix):
                return raw_key[: -len(suffix)], op
        return None, None

    for key, val in (match or {}).items():
        if key in _ALLOWED_EVENT_FIELDS:
            col = _safe_col(key)
            filters.append(col == val)
            continue

        # Allow simple operators on core event fields, e.g. dst_port_in: [22,80]
        base_field, op2 = _parse_field_op(key)
        if base_field and op2 and base_field in _ALLOWED_EVENT_FIELDS:
            col = _safe_col(base_field)
            if op2 in ("in", "not_in"):
                items = val if isinstance(val, list) else [val]
                items = [x for x in items if x is not None]
                if not items:
                    continue

                # best-effort cast
                if base_field in ("dst_port", "src_port", "bytes"):
                    cast_items = []
                    for x in items:
                        try:
                            cast_items.append(int(x))
                        except Exception:
                            pass
                    items = cast_items
                else:
                    items = [str(x) for x in items]

                if not items:
                    continue
                if op2 == "in":
                    filters.append(col.in_(items))
                else:
                    filters.append(or_(col.is_(None), ~col.in_(items)))
                continue

            if op2 in ("gte", "gt", "lte", "lt"):
                try:
                    target = float(val)
                except Exception:
                    continue
                # bytes can be BIGINT; cast to float for safe comparisons
                lhs = cast(col, Float) if base_field in ("bytes",) else col
                if op2 == "gte":
                    filters.append(lhs >= target)
                elif op2 == "gt":
                    filters.append(lhs > target)
                elif op2 == "lte":
                    filters.append(lhs <= target)
                else:
                    filters.append(lhs < target)
                continue

            if op2 == "neq":
                filters.append(col != val)
                continue

        if not key.startswith("extra_"):
            continue

        extra_key, op = _parse_extra_key(key)
        text_col = _extra_text_col(extra_key)

        if op in ("in", "not_in"):
            items = val if isinstance(val, list) else [val]
            items = [str(x) for x in items if x is not None]
            if not items:
                continue
            if op == "in":
                filters.append(text_col.in_(items))
            else:
                filters.append(or_(text_col.is_(None), ~text_col.in_(items)))
            continue

        if op in ("gte", "gt", "lte", "lt"):
            try:
                target = float(val)
            except Exception:
                continue
            is_numeric, num_col = _extra_numeric_col(extra_key)
            filters.append(is_numeric)
            if op == "gte":
                filters.append(num_col >= target)
            elif op == "gt":
                filters.append(num_col > target)
            elif op == "lte":
                filters.append(num_col <= target)
            else:
                filters.append(num_col < target)
            continue

        if op == "neq":
            filters.append(text_col != str(val).lower() if isinstance(val, bool) else text_col != str(val))
            continue

        if isinstance(val, bool):
            filters.append(text_col == ("true" if val else "false"))
        else:
            filters.append(text_col == str(val))

    return filters


def _enrich_alert_ips(
    db: Session,
    rule_id: str,
    match: Dict,
    group_key: Dict,
    since: datetime,
    until: datetime,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    dst_port: Optional[int],
) -> Tuple[Optional[str], Optional[str], Dict]:
    """Fill missing src_ip/dst_ip for specific rule families using supporting events.

    Returns: (src_ip, dst_ip, enrichment_details)
    """
    enrichment: Dict = {}
    rid = str(rule_id or "")

    # For DDoS/DoS/L7: compute Top-N attacker src_ips and unique cardinality.
    # Also fill alert.src_ip with the top attacker if missing.
    if rid.startswith(("ddos_", "dos_", "l7_")):
        dst = group_key.get("dst_ip") or dst_ip
        if dst:
            filters = _build_match_filters(match or {}, since, until)
            filters.append(NetEventModel.dst_ip == dst)

            gp_port = group_key.get("dst_port") or dst_port
            if gp_port is not None:
                try:
                    filters.append(NetEventModel.dst_port == int(gp_port))
                except Exception:
                    pass

            gp_proto = group_key.get("proto")
            if gp_proto:
                filters.append(NetEventModel.proto == str(gp_proto))

            filters.append(NetEventModel.src_ip.is_not(None))

            # Top 10 attackers
            stmt_top = (
                select(NetEventModel.src_ip, func.count().label("cnt"))
                .where(and_(*filters))
                .group_by(NetEventModel.src_ip)
                .order_by(func.count().desc())
                .limit(10)
            )
            rows = db.execute(stmt_top).all()

            top_list = []
            for r in rows:
                ip = r[0]
                cnt = int(r[1])
                if ip:
                    top_list.append({"ip": ip, "count": cnt})

            if top_list:
                enrichment["src_ips"] = top_list
                enrichment["top_src_ip"] = top_list[0]["ip"]
                enrichment["top_src_count"] = top_list[0]["count"]

                if src_ip is None or src_ip == "":
                    src_ip = top_list[0]["ip"]
                    enrichment["src_ip"] = "top_src_ip"

            # Unique attackers count
            stmt_uniq = select(func.count(func.distinct(NetEventModel.src_ip))).where(and_(*filters))
            uniq = db.execute(stmt_uniq).scalar() or 0
            enrichment["unique_src_ips"] = int(uniq)

    # For SSH bruteforce alerts grouped by src_ip only, infer dst_ip from most recent matching ssh_auth event.
    if (dst_ip is None or dst_ip == "") and rid.startswith("ssh_bruteforce_"):
        src = group_key.get("src_ip") or src_ip
        if src:
            filters = _build_match_filters(match or {}, since, until)
            filters.append(NetEventModel.src_ip == src)
            filters.append(NetEventModel.dst_ip.is_not(None))

            stmt = (
                select(NetEventModel.dst_ip)
                .where(and_(*filters))
                .order_by(NetEventModel.timestamp.desc())
                .limit(1)
            )

            row = db.execute(stmt).first()
            if row and row[0]:
                dst_ip = row[0]
                enrichment["dst_ip"] = "latest_dst_ip"

    return src_ip, dst_ip, enrichment


def _correlate_ddos_incidents(db: Session, now: datetime, created_alerts: List[AlertModel]) -> List[AlertModel]:
    horizon = timedelta(minutes=10)
    since = now - horizon

    ddos_alerts = [
        a
        for a in created_alerts
        if isinstance(a.rule_id, str)
        and (a.rule_id.startswith("ddos_") or a.rule_id.startswith("dos_") or a.rule_id.startswith("l7_"))
    ]

    if not ddos_alerts:
        return []

    out: List[AlertModel] = []

    for a in ddos_alerts:
        dst_ip = a.dst_ip
        if not dst_ip:
            continue

        stmt = (
            select(AlertModel.rule_id, func.count().label("cnt"))
            .where(
                and_(
                    AlertModel.created_at >= since,
                    AlertModel.dst_ip == dst_ip,
                    AlertModel.rule_id.in_(["port_scan_pcap_v1", "ssh_bruteforce_authlog_v2"]),
                )
            )
            .group_by(AlertModel.rule_id)
        )

        rows = db.execute(stmt).all()
        if not rows:
            continue

        correlated = {r.rule_id: int(r.cnt) for r in rows if r.rule_id}
        total = sum(correlated.values())
        if total <= 0:
            continue

        incident_rule_id = "incident_ddos_correlated_v1"

        cooldown_since = now - timedelta(minutes=10)
        existing = (
            db.execute(
                select(func.count())
                .select_from(AlertModel)
                .where(
                    and_(
                        AlertModel.created_at >= cooldown_since,
                        AlertModel.rule_id == incident_rule_id,
                        AlertModel.dst_ip == dst_ip,
                        AlertModel.dst_port == a.dst_port,
                    )
                )
            )
            .scalar()
            or 0
        )

        if int(existing) > 0:
            continue

        incident = AlertModel(
            rule_id=incident_rule_id,
            severity="critical",
            src_ip=None,
            dst_ip=dst_ip,
            dst_port=a.dst_port,
            mitre_tactic="impact",
            mitre_technique_id="T1498",
            mitre_technique=(technique_name("T1498") or "Network Denial of Service"),
            confidence=85,
            description="Potential incident: DDoS/DoS correlated with additional hostile activity",
            details={
                "type": "correlation",
                "window_seconds": int(horizon.total_seconds()),
                "correlated_rules": correlated,
                "base_rule_id": a.rule_id,
                "mitre": {
                    "tactic": "impact",
                    "technique_id": "T1498",
                    "technique": (technique_name("T1498") or "Network Denial of Service"),
                    "confidence": 85,
                },
            },
        )
        db.add(incident)
        out.append(incident)

    return out


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


def run_rules_once():
    now = datetime.utcnow()
    created_alerts: List[AlertModel] = []

    db = SessionLocal()
    try:
        base_rules = normalize_rule_list(load_baseline_rules(include_disabled=True))
        overrides = fetch_overrides(db)
        tunings = fetch_tuning(db)
        suppressions = fetch_suppressions(db)

        rules: List[Dict[str, Any]] = []
        max_cooldown_s = 0
        for base in base_rules:
            rid = base.get("id")
            eff, _ = apply_override(base, overrides.get(rid))
            eff = apply_tuning_and_suppressions(
                eff,
                tuning_row=tunings.get(str(rid)),
                suppression_rows=suppressions.get(str(rid)) or [],
            )
            rules.append(eff)
            try:
                max_cooldown_s = max(max_cooldown_s, int(_parse_window(eff.get("cooldown") or "0")))
            except Exception:
                pass

        # Build a "last alert" index that covers the maximum cooldown horizon.
        # Keep a sane floor to avoid pathological small horizons.
        horizon = timedelta(seconds=max(120, max_cooldown_s))
        recent_idx = _recent_alert_index(db, horizon)

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            if not _schedule_allows(rule, now):
                continue

            rule_id = rule.get("id")
            if not rule_id:
                continue

            rule_type = rule.get("type")
            severity = rule.get("severity", "low")
            description = rule.get("description", "")
            mitre = _extract_mitre_meta(rule)

            window_s = rule.get("window", "5m")
            cooldown_s = rule.get("cooldown", "10m")

            try:
                window = timedelta(seconds=_parse_window(window_s))
                cooldown = timedelta(seconds=_parse_window(cooldown_s))
            except Exception:
                window = timedelta(minutes=5)
                cooldown = timedelta(minutes=10)

            since = now - window
            until = now

            match = rule.get("match") or {}
            filters = _build_match_filters(match, since, until)

            if rule_type == "aggregate_count":
                group_by = rule.get("group_by")
                group_fields = group_by if isinstance(group_by, list) else [group_by] if isinstance(group_by, str) else []
                group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
                if not group_fields:
                    continue

                group_cols = [_safe_col(f) for f in group_fields]
                condition = rule.get("condition", {}) or {}
                min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                stmt = (
                    select(
                        *[c.label(f) for c, f in zip(group_cols, group_fields)],
                        func.count().label("count"),
                    )
                    .where(and_(*filters))
                    .group_by(*group_cols)
                )

                rows = db.execute(stmt).all()

                for row in rows:
                    group_key = {f: row._mapping.get(f) for f in group_fields}
                    count = int(row.count)

                    if min_events and count < min_events:
                        continue
                    if not _evaluate_condition(count, condition):
                        continue

                    src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                    src_ip, dst_ip, enrichment = _enrich_alert_ips(
                        db,
                        rule_id,
                        match or {},
                        group_key,
                        since,
                        until,
                        src_ip,
                        dst_ip,
                        dst_port,
                    )

                    last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                    if last_at and cooldown.total_seconds() > 0 and (now - last_at) < cooldown:
                        continue

                    sup_ctx = dict(group_key)
                    sup_ctx.update(
                        {
                            "rule_id": rule_id,
                            "severity": severity,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                        }
                    )
                    suppressed, _ = _is_suppressed(rule, sup_ctx, now)
                    if suppressed:
                        continue

                    details = {
                        "type": rule_type,
                        "group_by": group_fields,
                        "group_key": group_key,
                        "count": count,
                        "window_seconds": int(window.total_seconds()),
                        "enrichment": enrichment,
                        "rule_meta": {
                            "pack": rule.get("pack"),
                            "category": rule.get("category"),
                            "rule_version": int(rule.get("rule_version") or 1),
                        },
                    }
                    # Mirror to root for easier dashboards (optional but useful)
                    if enrichment.get("src_ips"):
                        details["src_ips"] = enrichment["src_ips"]
                        details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                    if mitre:
                        details["mitre"] = mitre
                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        mitre_tactic=mitre.get("tactic"),
                        mitre_technique_id=mitre.get("technique_id"),
                        mitre_technique=mitre.get("technique"),
                        confidence=int(mitre.get("confidence", 50) or 50),
                        description=description,
                        details=details,
                    )
                    db.add(alert)
                    created_alerts.append(alert)
                    _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

            elif rule_type == "distinct_count":
                condition = rule.get("condition", {}) or {}
                min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                distinct_field = rule.get("distinct_field")
                if not isinstance(distinct_field, str) or distinct_field not in _ALLOWED_EVENT_FIELDS:
                    continue

                distinct_col = _safe_col(distinct_field)
                filters2 = list(filters)
                filters2.append(distinct_col.is_not(None))

                group_by = rule.get("group_by")
                group_fields = group_by if isinstance(group_by, list) else [group_by] if isinstance(group_by, str) else []
                group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
                if not group_fields:
                    continue

                group_cols = [_safe_col(f) for f in group_fields]

                stmt = (
                    select(
                        *[c.label(f) for c, f in zip(group_cols, group_fields)],
                        func.count(func.distinct(distinct_col)).label("distinct_count"),
                        func.count().label("event_count"),
                    )
                    .where(and_(*filters2))
                    .group_by(*group_cols)
                )

                rows = db.execute(stmt).all()

                for row in rows:
                    group_key = {f: row._mapping.get(f) for f in group_fields}
                    distinct_count = int(row.distinct_count)
                    event_count = int(row.event_count)

                    if min_events and event_count < min_events:
                        continue
                    if not _evaluate_condition(distinct_count, condition):
                        continue

                    src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                    src_ip, dst_ip, enrichment = _enrich_alert_ips(
                        db,
                        rule_id,
                        match or {},
                        group_key,
                        since,
                        until,
                        src_ip,
                        dst_ip,
                        dst_port,
                    )

                    last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                    if last_at and cooldown.total_seconds() > 0 and (now - last_at) < cooldown:
                        continue

                    sup_ctx = dict(group_key)
                    sup_ctx.update(
                        {
                            "rule_id": rule_id,
                            "severity": severity,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                        }
                    )
                    suppressed, _ = _is_suppressed(rule, sup_ctx, now)
                    if suppressed:
                        continue

                    details = {
                        "type": rule_type,
                        "group_by": group_fields,
                        "group_key": group_key,
                        "distinct_field": distinct_field,
                        "distinct_count": distinct_count,
                        "event_count": event_count,
                        "window_seconds": int(window.total_seconds()),
                        "enrichment": enrichment,
                        "rule_meta": {
                            "pack": rule.get("pack"),
                            "category": rule.get("category"),
                            "rule_version": int(rule.get("rule_version") or 1),
                        },
                    }
                    if enrichment.get("src_ips"):
                        details["src_ips"] = enrichment["src_ips"]
                        details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                    if mitre:
                        details["mitre"] = mitre
                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        mitre_tactic=mitre.get("tactic"),
                        mitre_technique_id=mitre.get("technique_id"),
                        mitre_technique=mitre.get("technique"),
                        confidence=int(mitre.get("confidence", 50) or 50),
                        description=description,
                        details=details,
                    )
                    db.add(alert)
                    created_alerts.append(alert)
                    _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)

            elif rule_type == "multi_distinct":
                condition = rule.get("condition", {}) or {}
                min_events = int(rule.get("min_events") or condition.get("min_events") or 0)

                group_by = rule.get("group_by")
                group_fields = group_by if isinstance(group_by, list) else [group_by] if isinstance(group_by, str) else []
                group_fields = [f for f in group_fields if isinstance(f, str) and f in _ALLOWED_EVENT_FIELDS]
                if not group_fields:
                    continue

                distinct_conditions = rule.get("distinct_conditions") or []
                if not isinstance(distinct_conditions, list) or len(distinct_conditions) == 0:
                    continue

                # Validate distinct fields
                dcs = []
                for dc in distinct_conditions:
                    if not isinstance(dc, dict):
                        continue
                    f = dc.get("field")
                    if not isinstance(f, str) or f not in _ALLOWED_EVENT_FIELDS:
                        continue
                    dcs.append(dc)
                if not dcs:
                    continue

                group_cols = [_safe_col(f) for f in group_fields]
                # Build select list
                sel = [c.label(f) for c, f in zip(group_cols, group_fields)]
                sel.append(func.count().label("event_count"))
                for i, dc in enumerate(dcs):
                    f = dc.get("field")
                    sel.append(func.count(func.distinct(_safe_col(f))).label(f"d{i}"))

                stmt = select(*sel).where(and_(*filters)).group_by(*group_cols)
                rows = db.execute(stmt).all()

                for row in rows:
                    group_key = {f: row._mapping.get(f) for f in group_fields}
                    event_count = int(row.event_count)
                    if min_events and event_count < min_events:
                        continue

                    # Evaluate each distinct condition
                    distinct_result: Dict[str, int] = {}
                    ok = True
                    for i, dc in enumerate(dcs):
                        value = int(row._mapping.get(f"d{i}") or 0)
                        f = dc.get("field")
                        distinct_result[f] = value
                        if not _evaluate_condition(value, dc):
                            ok = False
                            break
                    if not ok:
                        continue

                    src_ip, dst_ip, dst_port = _extract_alert_key(group_key, match)

                    src_ip, dst_ip, enrichment = _enrich_alert_ips(
                        db,
                        rule_id,
                        match or {},
                        group_key,
                        since,
                        until,
                        src_ip,
                        dst_ip,
                        dst_port,
                    )

                    last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                    if last_at and cooldown.total_seconds() > 0 and (now - last_at) < cooldown:
                        continue

                    sup_ctx = dict(group_key)
                    sup_ctx.update(
                        {
                            "rule_id": rule_id,
                            "severity": severity,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                        }
                    )
                    suppressed, _ = _is_suppressed(rule, sup_ctx, now)
                    if suppressed:
                        continue

                    details = {
                        "type": rule_type,
                        "group_by": group_fields,
                        "group_key": group_key,
                        "event_count": event_count,
                        "distinct": distinct_result,
                        "window_seconds": int(window.total_seconds()),
                        "enrichment": enrichment,
                        "rule_meta": {
                            "pack": rule.get("pack"),
                            "category": rule.get("category"),
                            "rule_version": int(rule.get("rule_version") or 1),
                        },
                    }
                    if enrichment.get("src_ips"):
                        details["src_ips"] = enrichment["src_ips"]
                        details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                    if mitre:
                        details["mitre"] = mitre
                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        mitre_tactic=mitre.get("tactic"),
                        mitre_technique_id=mitre.get("technique_id"),
                        mitre_technique=mitre.get("technique"),
                        confidence=int(mitre.get("confidence", 50) or 50),
                        description=description,
                        details=details,
                    )
                    db.add(alert)
                    created_alerts.append(alert)
                    _index_add(recent_idx, rule_id, src_ip, dst_ip, dst_port)
            else:
                continue

        try:
            correlated = _correlate_ddos_incidents(db, now, created_alerts)
            if correlated:
                created_alerts.extend(correlated)
        except Exception:
            pass

        db.commit()
    finally:
        db.close()

    return created_alerts


def _parse_window(s: str) -> int:
    s = str(s).strip().lower()
    if s.endswith("ms"):
        return int(float(s[:-2]) / 1000.0)
    if s.endswith("s"):
        return int(float(s[:-1]))
    if s.endswith("m"):
        return int(float(s[:-1]) * 60)
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    return int(float(s))


def run_all_rules():
    return run_rules_once()
