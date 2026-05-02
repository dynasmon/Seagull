import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, cast, func, select, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import Float

from app.features.alerts.models import AlertModel
from app.features.events.worker_runtime import NetEventModel

_ALLOWED_EVENT_FIELDS = {
    "agent_id",
    "event_type",
    "src_ip",
    "dst_ip",
    "dst_port",
    "src_port",
    "proto",
    "bytes",
    "app_proto",
    "proc_name",
    "proc_parent_name",
    "fim_path",
    "fim_category",
    "heuristic_name",
    "heuristic_confidence",
}


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return float(default)
        return float(v)
    except Exception:
        return float(default)


def _as_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return int(default)
        return int(float(v))
    except Exception:
        return int(default)


def _extra_flow_direction(extra: Dict[str, Any]) -> str:
    if not isinstance(extra, dict):
        return ""
    return str(extra.get("flow_direction") or "").strip().lower()


def _extra_indicator_host(extra: Dict[str, Any]) -> str:
    if not isinstance(extra, dict):
        return ""
    host = str(extra.get("http_host") or extra.get("tls_sni") or "").strip().lower()
    if host:
        return host[:255]
    l7 = extra.get("l7")
    if isinstance(l7, dict):
        http = l7.get("http")
        if isinstance(http, dict):
            h = str(http.get("host") or "").strip().lower()
            if h:
                return h[:255]
    return ""


def _is_unusual_app_protocol_use(app_proto: str, dst_port: int, proto: str) -> bool:
    p = str(app_proto or "").strip().lower()
    tr = str(proto or "").strip().lower()
    d = int(dst_port or 0)
    if not p or d <= 0:
        return False
    if p == "dns" and d not in {53, 5353, 853}:
        return True
    if p == "http" and d in {22, 53}:
        return True
    if p == "tls" and d in {53, 123, 1900}:
        return True
    if p == "quic" and tr != "udp":
        return True
    if p == "dtls" and tr != "udp":
        return True
    return False


def _host_suspicion_reason(host: str) -> str:
    h = str(host or "").strip().lower().strip(".")
    if not h:
        return ""
    labels = [x for x in h.split(".") if x]
    if len(labels) >= 6:
        return "many_labels"
    if len(h) >= 72:
        return "long_host"
    alpha_num = sum(1 for c in h if c.isalnum())
    digits = sum(1 for c in h if c.isdigit())
    if alpha_num >= 20 and digits / max(alpha_num, 1) >= 0.35:
        return "digit_heavy_host"
    return ""


def _netevent_exists_recent(
    db: Session,
    *,
    event_type: str,
    agent_id: str,
    dst_ip: str,
    dst_port: int | None,
    fingerprint: str,
    since: datetime,
) -> bool:
    stmt = (
        select(NetEventModel.id)
        .where(
            NetEventModel.timestamp >= since,
            NetEventModel.event_type == event_type,
            NetEventModel.agent_id == agent_id,
            NetEventModel.dst_ip == dst_ip,
            NetEventModel.extra["fingerprint"].astext == fingerprint,
        )
        .limit(1)
    )
    if dst_port is None:
        stmt = stmt.where(NetEventModel.dst_port.is_(None))
    else:
        stmt = stmt.where(NetEventModel.dst_port == int(dst_port))
    return db.execute(stmt).scalar() is not None


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
    k = raw_key[len("extra_"):]

    for suffix, op in (
        ("_not_contains", "not_contains"),
        ("_contains_all", "contains_all"),
        ("_contains", "contains"),
        ("_startswith", "startswith"),
        ("_endswith", "endswith"),
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

        if op in ("contains", "not_contains", "contains_all", "startswith", "endswith"):
            items = val if isinstance(val, list) else [val]
            terms = [str(x).strip().lower() for x in items if str(x).strip()]
            if not terms:
                continue
            lower_col = func.lower(text_col)

            like_parts = []
            for term in terms:
                if op in ("contains", "not_contains", "contains_all"):
                    like_parts.append(lower_col.like(f"%{term}%"))
                elif op == "startswith":
                    like_parts.append(lower_col.like(f"{term}%"))
                else:
                    like_parts.append(lower_col.like(f"%{term}"))

            if op == "contains":
                filters.append(or_(*like_parts))
            elif op == "contains_all":
                filters.append(and_(*like_parts))
            elif op == "not_contains":
                filters.append(or_(text_col.is_(None), and_(*[~p for p in like_parts])))
            else:
                filters.append(or_(*like_parts))
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


def _as_str_set(values: Any) -> set[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return set()
    out: set[str] = set()
    for v in values:
        s = str(v or "").strip().lower()
        if s:
            out.add(s)
    return out


def _as_optional_str(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s


def _as_ctx_list(values: Any) -> set[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return set()
    out: set[str] = set()
    for v in values:
        s = _as_optional_str(v)
        if s:
            out.add(s)
    return out


def _as_int_set(values: Any) -> set[int]:
    if isinstance(values, (int, float)):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return set()
    out: set[int] = set()
    for v in values:
        try:
            out.add(int(v))
        except Exception:
            continue
    return out


def _ip_in_cidrs(ip_value: Any, cidrs: Any) -> bool:
    ip_s = str(ip_value or "").strip()
    if not ip_s:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_s)
    except Exception:
        return False

    if isinstance(cidrs, str):
        cidrs = [cidrs]
    if not isinstance(cidrs, (list, tuple, set)):
        return False

    for c in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(str(c).strip(), strict=False):
                return True
        except Exception:
            continue
    return False


def _selector_matches(selector: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    if not isinstance(selector, dict) or not selector:
        return False

    checks = 0
    c = ctx if isinstance(ctx, dict) else {}

    def _check_str_set(sel_key: str, ctx_keys: List[str]) -> bool:
        nonlocal checks
        expected = _as_str_set(selector.get(sel_key))
        if not expected:
            return True
        checks += 1
        actual_values = {_as_optional_str(c.get(k)) for k in ctx_keys}
        actual_values = {x for x in actual_values if x}
        return bool(actual_values.intersection(expected))

    def _check_int_set(sel_key: str, ctx_keys: List[str]) -> bool:
        nonlocal checks
        expected = _as_int_set(selector.get(sel_key))
        if not expected:
            return True
        checks += 1
        actual: set[int] = set()
        for k in ctx_keys:
            try:
                v = c.get(k)
                if v is None or v == "":
                    continue
                actual.add(int(v))
            except Exception:
                continue
        return bool(actual.intersection(expected))

    def _check_overlap(sel_key: str, ctx_keys: List[str]) -> bool:
        nonlocal checks
        expected = _as_str_set(selector.get(sel_key))
        if not expected:
            return True
        checks += 1
        actual: set[str] = set()
        for k in ctx_keys:
            actual.update(_as_ctx_list(c.get(k)))
        return bool(actual.intersection(expected))

    if not _check_str_set("src_ips", ["src_ip"]):
        return False
    if not _check_str_set("dst_ips", ["dst_ip"]):
        return False
    if not _check_str_set("agent_ids", ["agent_id"]):
        return False
    if not _check_str_set("protos", ["proto"]):
        return False
    if not _check_str_set("event_types", ["event_type"]):
        return False
    if not _check_str_set("rule_ids", ["rule_id"]):
        return False
    if not _check_str_set("path_categories", ["path_category", "fim_category"]):
        return False
    if not _check_str_set("usernames", ["username"]):
        return False
    if not _check_str_set("target_users", ["target_user"]):
        return False
    if not _check_str_set("proc_names", ["proc_name"]):
        return False
    if not _check_str_set("proc_parent_names", ["proc_parent_name"]):
        return False
    if not _check_str_set("hostnames", ["agent_hostname", "hostname"]):
        return False
    if not _check_str_set("agent_hostnames", ["agent_hostname", "hostname"]):
        return False
    if not _check_str_set("host_roles", ["agent_host_role", "host_role"]):
        return False
    if not _check_str_set("agent_roles", ["agent_host_role", "host_role"]):
        return False
    if not _check_str_set("environments", ["agent_environment", "environment"]):
        return False
    if not _check_str_set("envs", ["agent_environment", "environment"]):
        return False
    if not _check_int_set("dst_ports", ["dst_port"]):
        return False
    if not _check_int_set("src_ports", ["src_port"]):
        return False
    if not _check_overlap("tags", ["agent_tags", "tags"]):
        return False
    if not _check_overlap("agent_tags", ["agent_tags", "tags"]):
        return False

    src_cidrs = selector.get("src_cidrs")
    if src_cidrs:
        checks += 1
        if not _ip_in_cidrs(c.get("src_ip"), src_cidrs):
            return False

    dst_cidrs = selector.get("dst_cidrs")
    if dst_cidrs:
        checks += 1
        if not _ip_in_cidrs(c.get("dst_ip"), dst_cidrs):
            return False

    known_keys = {
        "src_ips",
        "dst_ips",
        "agent_ids",
        "protos",
        "event_types",
        "rule_ids",
        "path_categories",
        "usernames",
        "target_users",
        "proc_names",
        "proc_parent_names",
        "hostnames",
        "agent_hostnames",
        "host_roles",
        "agent_roles",
        "environments",
        "envs",
        "dst_ports",
        "src_ports",
        "tags",
        "agent_tags",
        "src_cidrs",
        "dst_cidrs",
    }
    for k, expected in selector.items():
        if k in known_keys:
            continue
        if isinstance(expected, dict):
            continue
        checks += 1
        actual = c.get(str(k))
        if isinstance(expected, list):
            opts = _as_str_set(expected)
            if _as_optional_str(actual) not in opts:
                return False
        else:
            if _as_optional_str(actual) != _as_optional_str(expected):
                return False

    return checks > 0


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
