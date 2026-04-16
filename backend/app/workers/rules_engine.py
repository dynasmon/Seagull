import json
import ipaddress
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from zoneinfo import ZoneInfo

import yaml
from sqlalchemy import and_, cast, func, select, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql.sqltypes import Float

from app.core.config import settings
from app.core.db import SessionLocal
from app.features.agents.models import AgentModel
from app.features.alerts.models import AlertModel
from app.features.alerts.realtime import publish_alert_created_from_row
from app.features.alerts.rule_registry_runtime import (
    apply_override,
    apply_tuning_and_suppressions,
    fetch_overrides,
    fetch_suppressions,
    fetch_tuning,
    load_baseline_rules,
    normalize_rule_list,
)
from app.features.events.worker_runtime import NetEventModel

from app.shared.taxonomy.catalog import technique_name

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


def _build_beacon_candidates(db: Session, now: datetime) -> List[Dict[str, Any]]:
    win_s = max(300, int(settings.SEAGULL_HEUR_BEACON_WINDOW_SECONDS or 3600))
    min_events = max(4, int(settings.SEAGULL_HEUR_BEACON_MIN_EVENTS or 7))
    min_interval = max(2.0, float(settings.SEAGULL_HEUR_BEACON_MIN_INTERVAL_SECONDS or 8))
    max_interval = max(min_interval, float(settings.SEAGULL_HEUR_BEACON_MAX_INTERVAL_SECONDS or 900))
    max_jitter = max(0.01, min(1.0, float(settings.SEAGULL_HEUR_BEACON_MAX_JITTER or 0.22)))
    max_rows = max(1000, int(settings.SEAGULL_HEUR_MAX_ROWS or 50000))

    since = now - timedelta(seconds=win_s)
    rows = db.execute(
        select(
            NetEventModel.agent_id,
            NetEventModel.timestamp,
            NetEventModel.src_ip,
            NetEventModel.dst_ip,
            NetEventModel.dst_port,
            NetEventModel.proto,
            NetEventModel.bytes,
            NetEventModel.app_proto,
            NetEventModel.extra,
        ).where(
            NetEventModel.timestamp >= since,
            NetEventModel.event_type.in_(["flow", "l7_flow"]),
            NetEventModel.dst_ip.is_not(None),
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(max_rows)
    ).all()

    groups: Dict[Tuple[str, str, int, str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        extra = r.extra if isinstance(r.extra, dict) else {}
        if _extra_flow_direction(extra) != "outbound_from_local":
            continue
        agent_id = str(r.agent_id or "").strip()
        src_ip = str(r.src_ip or "").strip()
        dst_ip = str(r.dst_ip or "").strip()
        if not agent_id or not dst_ip:
            continue
        dst_port = _as_int(r.dst_port, 0)
        proto = str(r.proto or "").strip().lower() or "tcp"
        host = _extra_indicator_host(extra)
        key = (agent_id, dst_ip, dst_port, proto, host)
        groups.setdefault(key, []).append(
            {
                "timestamp": r.timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
                "host": host,
                "app_proto": str(r.app_proto or extra.get("app_proto") or "").strip().lower(),
                "bytes": _as_int(r.bytes, 0),
            }
        )

    out: List[Dict[str, Any]] = []
    for key, items in groups.items():
        if len(items) < min_events:
            continue
        items.sort(key=lambda x: x["timestamp"])
        ivals: List[float] = []
        for i in range(1, len(items)):
            dt = (items[i]["timestamp"] - items[i - 1]["timestamp"]).total_seconds()
            if dt > 0:
                ivals.append(dt)
        if len(ivals) < max(3, min_events - 2):
            continue

        mean = sum(ivals) / max(1, len(ivals))
        if mean < min_interval or mean > max_interval:
            continue
        var = sum((x - mean) ** 2 for x in ivals) / max(1, len(ivals))
        stdev = math.sqrt(max(var, 0.0))
        cv = stdev / mean if mean > 0 else 1.0
        if cv > max_jitter:
            continue

        last = items[-1]
        confidence = int(min(99, max(55, 62 + (1.0-cv)*25 + min(len(items), 20)*0.8)))
        unusual_app = _is_unusual_app_protocol_use(last["app_proto"], int(last["dst_port"]), last["proto"])
        host_reason = _host_suspicion_reason(key[4])
        if unusual_app:
            confidence = min(99, confidence + 6)
        if host_reason:
            confidence = min(99, confidence + 4)
        out.append(
            {
                "agent_id": key[0],
                "src_ip": last["src_ip"],
                "dst_ip": key[1],
                "dst_port": key[2] if key[2] > 0 else None,
                "proto": key[3],
                "host": key[4],
                "app_proto": last["app_proto"],
                "sample_count": len(items),
                "interval_mean_s": round(mean, 3),
                "interval_stdev_s": round(stdev, 3),
                "interval_jitter_cv": round(cv, 4),
                "bytes_total": sum(int(x["bytes"]) for x in items),
                "confidence": confidence,
                "unusual_app_proto_use": unusual_app,
                "host_suspicion_reason": host_reason,
            }
        )
    return out


def _build_exfil_candidates(db: Session, now: datetime) -> List[Dict[str, Any]]:
    baseline_s = max(3600, int(settings.SEAGULL_HEUR_EXFIL_BASELINE_SECONDS or 86400))
    recent_s = max(120, int(settings.SEAGULL_HEUR_EXFIL_WINDOW_SECONDS or 600))
    min_events = max(4, int(settings.SEAGULL_HEUR_EXFIL_MIN_EVENTS or 8))
    min_recent_bytes = max(1024 * 1024, int(settings.SEAGULL_HEUR_EXFIL_MIN_BYTES or 8 * 1024 * 1024))
    spike_factor = max(1.0, float(settings.SEAGULL_HEUR_EXFIL_SPIKE_FACTOR or 3.0))
    rare_baseline_events = max(1, int(settings.SEAGULL_HEUR_EXFIL_RARE_BASELINE_EVENTS or 5))
    max_rows = max(1000, int(settings.SEAGULL_HEUR_MAX_ROWS or 50000))

    since = now - timedelta(seconds=baseline_s)
    recent_since = now - timedelta(seconds=recent_s)
    rows = db.execute(
        select(
            NetEventModel.agent_id,
            NetEventModel.timestamp,
            NetEventModel.src_ip,
            NetEventModel.dst_ip,
            NetEventModel.dst_port,
            NetEventModel.proto,
            NetEventModel.bytes,
            NetEventModel.app_proto,
            NetEventModel.extra,
        ).where(
            NetEventModel.timestamp >= since,
            NetEventModel.event_type.in_(["flow", "l7_flow"]),
            NetEventModel.dst_ip.is_not(None),
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(max_rows)
    ).all()

    groups: Dict[Tuple[str, str, int, str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        extra = r.extra if isinstance(r.extra, dict) else {}
        if _extra_flow_direction(extra) != "outbound_from_local":
            continue
        agent_id = str(r.agent_id or "").strip()
        src_ip = str(r.src_ip or "").strip()
        dst_ip = str(r.dst_ip or "").strip()
        if not agent_id or not dst_ip:
            continue
        dst_port = _as_int(r.dst_port, 0)
        proto = str(r.proto or "").strip().lower() or "tcp"
        host = _extra_indicator_host(extra)
        key = (agent_id, dst_ip, dst_port, proto, host)
        groups.setdefault(key, []).append(
            {
                "timestamp": r.timestamp,
                "src_ip": src_ip,
                "bytes": max(0, _as_int(r.bytes, 0)),
                "app_proto": str(r.app_proto or extra.get("app_proto") or "").strip().lower(),
            }
        )

    out: List[Dict[str, Any]] = []
    for key, items in groups.items():
        recent = [x for x in items if x["timestamp"] >= recent_since]
        if len(recent) < min_events:
            continue
        baseline = [x for x in items if x["timestamp"] < recent_since]

        recent_bytes = sum(int(x["bytes"]) for x in recent)
        baseline_bytes = sum(int(x["bytes"]) for x in baseline)
        if recent_bytes < min_recent_bytes:
            continue
        spike_ok = baseline_bytes <= 0 or recent_bytes >= int(float(max(1, baseline_bytes)) * spike_factor)
        rare_ok = len(baseline) <= rare_baseline_events
        if not (spike_ok and rare_ok):
            continue

        latest = max(recent, key=lambda x: x["timestamp"])
        confidence = 62
        if rare_ok:
            confidence += 12
        if baseline_bytes <= 0:
            confidence += 10
        if recent_bytes >= 25 * 1024 * 1024:
            confidence += 8
        unusual_app = _is_unusual_app_protocol_use(latest["app_proto"], key[2], key[3])
        host_reason = _host_suspicion_reason(key[4])
        if unusual_app:
            confidence += 6
        if host_reason:
            confidence += 4
        confidence = min(99, confidence)

        out.append(
            {
                "agent_id": key[0],
                "src_ip": latest["src_ip"],
                "dst_ip": key[1],
                "dst_port": key[2] if key[2] > 0 else None,
                "proto": key[3],
                "host": key[4],
                "app_proto": latest["app_proto"],
                "recent_events": len(recent),
                "baseline_events": len(baseline),
                "recent_bytes": recent_bytes,
                "baseline_bytes": baseline_bytes,
                "spike_factor_observed": round(float(recent_bytes) / float(max(1, baseline_bytes)), 3) if baseline_bytes > 0 else None,
                "confidence": confidence,
                "unusual_app_proto_use": unusual_app,
                "host_suspicion_reason": host_reason,
            }
        )
    return out


def _has_exec_pattern(extra: Dict[str, Any], patterns: set[str]) -> bool:
    if not isinstance(extra, dict) or not patterns:
        return False
    p0 = str(extra.get("exec_pattern") or "").strip().lower()
    if p0 and p0 in patterns:
        return True
    items = extra.get("exec_patterns")
    if isinstance(items, list):
        for p in items:
            s = str(p or "").strip().lower()
            if s and s in patterns:
                return True
    return False


def _suspicious_activity_by_agent(
    db: Session,
    *,
    now: datetime,
    agent_ids: List[str],
    lookback_seconds: int,
) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    ids = [str(x or "").strip() for x in agent_ids if str(x or "").strip()]
    if not ids:
        return out

    since = now - timedelta(seconds=max(60, int(lookback_seconds or 900)))
    rows = db.execute(
        select(NetEventModel.agent_id, NetEventModel.event_type, NetEventModel.extra).where(
            NetEventModel.timestamp >= since,
            NetEventModel.agent_id.in_(ids),
            NetEventModel.event_type.in_(
                [
                    "proc_exec",
                    "persistence_systemd",
                    "persistence_cron",
                    "ssh_key_change",
                    "fim_change",
                ]
            ),
        )
    ).all()

    suspicious_exec_patterns = {"remote_fetch_exec", "reverse_shell", "service_shell_child", "lolbin"}
    for r in rows:
        aid = str(r.agent_id or "").strip()
        if not aid:
            continue
        bucket = out.setdefault(
            aid,
            {
                "suspicious_exec_hits": 0,
                "persistence_hits": 0,
                "tamper_hits": 0,
            },
        )
        et = str(r.event_type or "").strip().lower()
        extra = r.extra if isinstance(r.extra, dict) else {}
        if et == "proc_exec":
            if _has_exec_pattern(extra, suspicious_exec_patterns):
                bucket["suspicious_exec_hits"] += 1
            continue
        if et in {"persistence_systemd", "persistence_cron", "ssh_key_change"}:
            bucket["persistence_hits"] += 1
            continue
        if et == "fim_change" and str(extra.get("tamper_related") or "").strip().lower() in {"1", "true", "yes"}:
            bucket["tamper_hits"] += 1
    return out


def _build_egress_anomaly_candidates(db: Session, now: datetime) -> List[Dict[str, Any]]:
    baseline_s = max(1800, int(settings.SEAGULL_HEUR_EGRESS_BASELINE_SECONDS or 21600))
    recent_s = max(120, int(settings.SEAGULL_HEUR_EGRESS_WINDOW_SECONDS or 900))
    min_events = max(3, int(settings.SEAGULL_HEUR_EGRESS_MIN_EVENTS or 5))
    min_recent_bytes = max(256 * 1024, int(settings.SEAGULL_HEUR_EGRESS_MIN_BYTES or 2 * 1024 * 1024))
    spike_factor = max(1.0, float(settings.SEAGULL_HEUR_EGRESS_SPIKE_FACTOR or 2.5))
    rare_baseline_events = max(1, int(settings.SEAGULL_HEUR_EGRESS_RARE_BASELINE_EVENTS or 3))
    correlation_s = max(120, int(settings.SEAGULL_HEUR_EGRESS_CORRELATION_SECONDS or 900))
    max_rows = max(1000, int(settings.SEAGULL_HEUR_MAX_ROWS or 50000))

    since = now - timedelta(seconds=baseline_s)
    recent_since = now - timedelta(seconds=recent_s)
    rows = db.execute(
        select(
            NetEventModel.agent_id,
            NetEventModel.timestamp,
            NetEventModel.src_ip,
            NetEventModel.dst_ip,
            NetEventModel.dst_port,
            NetEventModel.proto,
            NetEventModel.bytes,
            NetEventModel.app_proto,
            NetEventModel.extra,
        ).where(
            NetEventModel.timestamp >= since,
            NetEventModel.event_type.in_(["flow", "l7_flow"]),
            NetEventModel.dst_ip.is_not(None),
        )
        .order_by(NetEventModel.timestamp.desc())
        .limit(max_rows)
    ).all()

    groups: Dict[Tuple[str, str, int, str, str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        extra = r.extra if isinstance(r.extra, dict) else {}
        if _extra_flow_direction(extra) != "outbound_from_local":
            continue
        agent_id = str(r.agent_id or "").strip()
        src_ip = str(r.src_ip or "").strip()
        dst_ip = str(r.dst_ip or "").strip()
        if not agent_id or not dst_ip:
            continue
        dst_port = _as_int(r.dst_port, 0)
        proto = str(r.proto or "").strip().lower() or "tcp"
        app_proto = str(r.app_proto or extra.get("app_proto") or "").strip().lower()
        host = _extra_indicator_host(extra)
        key = (agent_id, dst_ip, dst_port, proto, host, app_proto)
        groups.setdefault(key, []).append(
            {
                "timestamp": r.timestamp,
                "src_ip": src_ip,
                "bytes": max(0, _as_int(r.bytes, 0)),
            }
        )

    suspicious_ctx = _suspicious_activity_by_agent(
        db,
        now=now,
        agent_ids=[k[0] for k in groups.keys()],
        lookback_seconds=correlation_s,
    )
    risky_ports = {4444, 1337, 6667, 31337}

    out: List[Dict[str, Any]] = []
    for key, items in groups.items():
        recent = [x for x in items if x["timestamp"] >= recent_since]
        if len(recent) < min_events:
            continue
        baseline = [x for x in items if x["timestamp"] < recent_since]
        recent_bytes = sum(int(x["bytes"]) for x in recent)
        baseline_bytes = sum(int(x["bytes"]) for x in baseline)
        if recent_bytes < min_recent_bytes:
            continue

        rare_ok = len(baseline) <= rare_baseline_events
        spike_ok = baseline_bytes <= 0 or recent_bytes >= int(float(max(1, baseline_bytes)) * spike_factor)
        unusual_app = _is_unusual_app_protocol_use(key[5], key[2], key[3])
        risky_port = key[2] in risky_ports if key[2] > 0 else False
        host_reason = _host_suspicion_reason(key[4])
        agent_ctx = suspicious_ctx.get(key[0]) or {}
        exec_hits = int(agent_ctx.get("suspicious_exec_hits") or 0)
        persistence_hits = int(agent_ctx.get("persistence_hits") or 0)
        tamper_hits = int(agent_ctx.get("tamper_hits") or 0)

        if not (rare_ok or spike_ok or unusual_app or risky_port or host_reason):
            continue

        reason_kind = "bursty_outbound"
        if rare_ok and exec_hits > 0:
            reason_kind = "rare_destination_after_suspicious_exec"
        elif rare_ok and persistence_hits > 0:
            reason_kind = "bursty_outbound_after_persistence"
        elif rare_ok and unusual_app:
            reason_kind = "rare_destination_unusual_protocol"
        elif risky_port:
            reason_kind = "suspicious_destination_port"
        elif host_reason:
            reason_kind = "suspicious_host_pattern"

        confidence = 56
        if rare_ok:
            confidence += 10
        if spike_ok:
            confidence += 8
        if unusual_app:
            confidence += 8
        if risky_port:
            confidence += 8
        if host_reason:
            confidence += 5
        if exec_hits > 0:
            confidence += 10
        if persistence_hits > 0:
            confidence += 7
        if tamper_hits > 0:
            confidence += 6
        if recent_bytes >= 16 * 1024 * 1024:
            confidence += 6
        confidence = min(99, confidence)

        latest = max(recent, key=lambda x: x["timestamp"])
        out.append(
            {
                "agent_id": key[0],
                "src_ip": latest["src_ip"],
                "dst_ip": key[1],
                "dst_port": key[2] if key[2] > 0 else None,
                "proto": key[3],
                "host": key[4],
                "app_proto": key[5],
                "recent_events": len(recent),
                "baseline_events": len(baseline),
                "recent_bytes": recent_bytes,
                "baseline_bytes": baseline_bytes,
                "confidence": int(confidence),
                "reason_kind": reason_kind,
                "unusual_app_proto_use": unusual_app,
                "host_suspicion_reason": host_reason,
                "suspicious_exec_hits": exec_hits,
                "persistence_hits": persistence_hits,
                "tamper_hits": tamper_hits,
            }
        )
    return out


def _emit_heuristic_signals(db: Session, now: datetime) -> Tuple[List[NetEventModel], List[AlertModel]]:
    derived_events: List[NetEventModel] = []
    derived_alerts: List[AlertModel] = []
    beacon_cd = max(120, int(settings.SEAGULL_HEUR_BEACON_COOLDOWN_SECONDS or 900))
    exfil_cd = max(120, int(settings.SEAGULL_HEUR_EXFIL_COOLDOWN_SECONDS or 1200))
    egress_cd = max(120, int(settings.SEAGULL_HEUR_EGRESS_COOLDOWN_SECONDS or 1200))

    for cand in _build_beacon_candidates(db, now):
        fp = f"beacon:{cand['agent_id']}:{cand['dst_ip']}:{cand.get('dst_port') or 0}:{cand['proto']}:{cand.get('host') or '-'}"
        if _netevent_exists_recent(
            db,
            event_type="beacon_suspect",
            agent_id=str(cand["agent_id"]),
            dst_ip=str(cand["dst_ip"]),
            dst_port=cand.get("dst_port"),
            fingerprint=fp,
            since=now - timedelta(seconds=beacon_cd),
        ):
            continue
        extra = {
            "heuristic_name": "beacon_periodic_outbound",
            "heuristic_kind": "beaconing",
            "reason_kind": "low_jitter_periodic_interval",
            "fingerprint": fp,
            "confidence": int(cand["confidence"]),
            "sample_count": int(cand["sample_count"]),
            "interval_mean_s": cand["interval_mean_s"],
            "interval_stdev_s": cand["interval_stdev_s"],
            "interval_jitter_cv": cand["interval_jitter_cv"],
            "dst_host": cand.get("host"),
            "app_proto": cand.get("app_proto"),
            "unusual_app_proto_use": bool(cand.get("unusual_app_proto_use")),
            "host_suspicion_reason": cand.get("host_suspicion_reason"),
            "bytes_total": int(cand["bytes_total"]),
            "mitre": {"tactic": "command_and_control", "technique_id": "T1071", "technique": technique_name("T1071") or "Application Layer Protocol", "confidence": int(cand["confidence"])},
            "reasons": ["periodic outbound intervals", "low jitter (coefficient of variation)", "repeated destination tuple"],
        }
        if cand.get("unusual_app_proto_use"):
            extra["reasons"].append("unusual application protocol for destination port")
        if cand.get("host_suspicion_reason"):
            extra["reasons"].append(f"suspicious host pattern: {cand.get('host_suspicion_reason')}")
        ev = NetEventModel(
            agent_id=str(cand["agent_id"]),
            event_type="beacon_suspect",
            schema_version=1,
            timestamp=now,
            src_ip=str(cand["src_ip"] or "") or None,
            dst_ip=str(cand["dst_ip"] or "") or None,
            dst_port=cand.get("dst_port"),
            proto=str(cand.get("proto") or "") or None,
            bytes=int(cand["bytes_total"]),
            app_proto=str(cand.get("app_proto") or "") or None,
            heuristic_name="beacon_periodic_outbound",
            heuristic_confidence=int(cand["confidence"]),
            extra=extra,
        )
        db.add(ev)
        derived_events.append(ev)
        sev = "medium" if int(cand["confidence"]) < 80 else "high"
        derived_alerts.append(
            AlertModel(
                rule_id="heuristic_beacon_periodic_v1",
                severity=sev,
                src_ip=str(cand["src_ip"] or "") or None,
                dst_ip=str(cand["dst_ip"] or "") or None,
                dst_port=cand.get("dst_port"),
                mitre_tactic="command_and_control",
                mitre_technique_id="T1071",
                mitre_technique=technique_name("T1071") or "Application Layer Protocol",
                confidence=int(cand["confidence"]),
                description="Suspicious outbound beaconing pattern detected",
                details=extra,
            )
        )

    for cand in _build_exfil_candidates(db, now):
        fp = f"exfil:{cand['agent_id']}:{cand['dst_ip']}:{cand.get('dst_port') or 0}:{cand['proto']}:{cand.get('host') or '-'}"
        if _netevent_exists_recent(
            db,
            event_type="exfil_suspect",
            agent_id=str(cand["agent_id"]),
            dst_ip=str(cand["dst_ip"]),
            dst_port=cand.get("dst_port"),
            fingerprint=fp,
            since=now - timedelta(seconds=exfil_cd),
        ):
            continue
        extra = {
            "heuristic_name": "exfil_burst_rare_destination",
            "heuristic_kind": "exfiltration",
            "reason_kind": "burst_upload_rare_dest",
            "fingerprint": fp,
            "confidence": int(cand["confidence"]),
            "recent_events": int(cand["recent_events"]),
            "baseline_events": int(cand["baseline_events"]),
            "recent_bytes": int(cand["recent_bytes"]),
            "baseline_bytes": int(cand["baseline_bytes"]),
            "spike_factor_observed": cand.get("spike_factor_observed"),
            "dst_host": cand.get("host"),
            "app_proto": cand.get("app_proto"),
            "unusual_app_proto_use": bool(cand.get("unusual_app_proto_use")),
            "host_suspicion_reason": cand.get("host_suspicion_reason"),
            "mitre": {"tactic": "exfiltration", "technique_id": "T1048", "technique": technique_name("T1048") or "Exfiltration Over Alternative Protocol", "confidence": int(cand["confidence"])},
            "reasons": ["burst outbound bytes in short window", "rare destination for this agent baseline", "traffic spike above baseline ratio"],
        }
        if cand.get("unusual_app_proto_use"):
            extra["reasons"].append("unusual application protocol for destination port")
        if cand.get("host_suspicion_reason"):
            extra["reasons"].append(f"suspicious host pattern: {cand.get('host_suspicion_reason')}")
        ev = NetEventModel(
            agent_id=str(cand["agent_id"]),
            event_type="exfil_suspect",
            schema_version=1,
            timestamp=now,
            src_ip=str(cand["src_ip"] or "") or None,
            dst_ip=str(cand["dst_ip"] or "") or None,
            dst_port=cand.get("dst_port"),
            proto=str(cand.get("proto") or "") or None,
            bytes=int(cand["recent_bytes"]),
            app_proto=str(cand.get("app_proto") or "") or None,
            heuristic_name="exfil_burst_rare_destination",
            heuristic_confidence=int(cand["confidence"]),
            extra=extra,
        )
        db.add(ev)
        derived_events.append(ev)
        derived_alerts.append(
            AlertModel(
                rule_id="heuristic_exfil_burst_v1",
                severity="high",
                src_ip=str(cand["src_ip"] or "") or None,
                dst_ip=str(cand["dst_ip"] or "") or None,
                dst_port=cand.get("dst_port"),
                mitre_tactic="exfiltration",
                mitre_technique_id="T1048",
                mitre_technique=technique_name("T1048") or "Exfiltration Over Alternative Protocol",
                confidence=int(cand["confidence"]),
                description="Potential data exfiltration pattern detected",
                details=extra,
            )
        )

    for cand in _build_egress_anomaly_candidates(db, now):
        fp = f"egress:{cand['agent_id']}:{cand['dst_ip']}:{cand.get('dst_port') or 0}:{cand['proto']}:{cand.get('host') or '-'}"
        if _netevent_exists_recent(
            db,
            event_type="egress_anomaly",
            agent_id=str(cand["agent_id"]),
            dst_ip=str(cand["dst_ip"]),
            dst_port=cand.get("dst_port"),
            fingerprint=fp,
            since=now - timedelta(seconds=egress_cd),
        ):
            continue
        reasons = [
            "outbound connection profile deviates from host baseline",
            "destination is rare or burst behavior exceeds baseline",
        ]
        if int(cand.get("suspicious_exec_hits") or 0) > 0:
            reasons.append("recent suspicious process execution on same host")
        if int(cand.get("persistence_hits") or 0) > 0:
            reasons.append("recent persistence change on same host")
        if int(cand.get("tamper_hits") or 0) > 0:
            reasons.append("recent defense evasion/tamper signal on same host")
        if cand.get("unusual_app_proto_use"):
            reasons.append("application protocol is unusual for destination port")
        if cand.get("host_suspicion_reason"):
            reasons.append(f"suspicious destination host pattern: {cand.get('host_suspicion_reason')}")

        extra = {
            "heuristic_name": "egress_contextual_anomaly",
            "heuristic_kind": "egress_anomaly",
            "reason_kind": cand.get("reason_kind"),
            "fingerprint": fp,
            "confidence": int(cand["confidence"]),
            "recent_events": int(cand["recent_events"]),
            "baseline_events": int(cand["baseline_events"]),
            "recent_bytes": int(cand["recent_bytes"]),
            "baseline_bytes": int(cand["baseline_bytes"]),
            "dst_host": cand.get("host"),
            "app_proto": cand.get("app_proto"),
            "unusual_app_proto_use": bool(cand.get("unusual_app_proto_use")),
            "host_suspicion_reason": cand.get("host_suspicion_reason"),
            "suspicious_exec_hits": int(cand.get("suspicious_exec_hits") or 0),
            "persistence_hits": int(cand.get("persistence_hits") or 0),
            "tamper_hits": int(cand.get("tamper_hits") or 0),
            "mitre": {
                "tactic": "command_and_control",
                "technique_id": "T1071",
                "technique": technique_name("T1071") or "Application Layer Protocol",
                "confidence": int(cand["confidence"]),
            },
            "reasons": reasons,
        }
        ev = NetEventModel(
            agent_id=str(cand["agent_id"]),
            event_type="egress_anomaly",
            schema_version=1,
            timestamp=now,
            src_ip=str(cand["src_ip"] or "") or None,
            dst_ip=str(cand["dst_ip"] or "") or None,
            dst_port=cand.get("dst_port"),
            proto=str(cand.get("proto") or "") or None,
            bytes=int(cand["recent_bytes"]),
            app_proto=str(cand.get("app_proto") or "") or None,
            heuristic_name="egress_contextual_anomaly",
            heuristic_confidence=int(cand["confidence"]),
            extra=extra,
        )
        db.add(ev)
        derived_events.append(ev)
    return derived_events, derived_alerts



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
    incident_rule_id = "incident_ddos_correlated_v1"

    dst_ips = sorted({str(a.dst_ip) for a in ddos_alerts if a.dst_ip})
    if not dst_ips:
        return []

    correlated_rows = db.execute(
        select(
            AlertModel.dst_ip.label("dst_ip"),
            AlertModel.rule_id.label("rule_id"),
            func.count().label("cnt"),
        )
        .where(
            and_(
                AlertModel.created_at >= since,
                AlertModel.dst_ip.in_(dst_ips),
                AlertModel.rule_id.in_(["port_scan_pcap_v1", "ssh_bruteforce_authlog_v2"]),
            )
        )
        .group_by(AlertModel.dst_ip, AlertModel.rule_id)
    ).all()

    by_dst: Dict[str, Dict[str, int]] = {}
    for row in correlated_rows:
        if not row.dst_ip or not row.rule_id:
            continue
        by_dst.setdefault(str(row.dst_ip), {})[str(row.rule_id)] = int(row.cnt or 0)

    cooldown_since = now - timedelta(minutes=10)
    candidate_pairs = {(str(a.dst_ip), int(a.dst_port) if a.dst_port is not None else None) for a in ddos_alerts if a.dst_ip}
    existing_rows = db.execute(
        select(AlertModel.dst_ip, AlertModel.dst_port)
        .where(
            and_(
                AlertModel.created_at >= cooldown_since,
                AlertModel.rule_id == incident_rule_id,
                AlertModel.dst_ip.in_(dst_ips),
            )
        )
    ).all()
    existing_pairs = {(str(r.dst_ip), int(r.dst_port) if r.dst_port is not None else None) for r in existing_rows}

    for a in ddos_alerts:
        dst_ip = a.dst_ip
        if not dst_ip:
            continue
        correlated = by_dst.get(str(dst_ip)) or {}
        if sum(correlated.values()) <= 0:
            continue
        pair = (str(dst_ip), int(a.dst_port) if a.dst_port is not None else None)
        if pair in existing_pairs:
            continue
        if pair not in candidate_pairs:
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
        existing_pairs.add(pair)

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


def _resolve_tuning_eval(
    rule: Dict[str, Any],
    *,
    ctx: Dict[str, Any],
    base_min_events: int,
    base_condition: Dict[str, Any],
    base_cooldown_seconds: int,
    base_severity: str,
) -> Dict[str, Any]:
    out = {
        "min_events": int(base_min_events),
        "condition": dict(base_condition or {}),
        "cooldown_seconds": int(max(0, base_cooldown_seconds)),
        "severity": str(base_severity or "low"),
        "applied_scopes": [],
    }
    tuning = rule.get("tuning") if isinstance(rule.get("tuning"), dict) else {}
    scopes = tuning.get("threshold_scopes") or tuning.get("scopes") or []
    if not isinstance(scopes, list) or not scopes:
        return out

    for i, scope in enumerate(scopes):
        if not isinstance(scope, dict):
            continue
        if scope.get("enabled") is False:
            continue
        when = scope.get("when") if isinstance(scope.get("when"), dict) else {}
        if when and not _selector_matches(when, ctx):
            continue
        if when == {}:
            continue

        name = str(scope.get("name") or f"scope_{i+1}").strip()
        out["applied_scopes"].append(name)

        if scope.get("min_events") is not None:
            try:
                out["min_events"] = max(0, int(scope.get("min_events")))
            except Exception:
                pass

        if isinstance(scope.get("condition"), dict):
            cond = scope.get("condition") or {}
            out["condition"] = dict(cond)
        elif scope.get("condition_value") is not None:
            try:
                v = int(scope.get("condition_value"))
                cur = dict(out.get("condition") or {})
                cur["value"] = v
                if not cur.get("operator"):
                    cur["operator"] = ">="
                out["condition"] = cur
            except Exception:
                pass

        cooldown_raw = scope.get("cooldown")
        if cooldown_raw is not None and str(cooldown_raw).strip():
            try:
                out["cooldown_seconds"] = max(0, int(_parse_window(str(cooldown_raw))))
            except Exception:
                pass

        sev_raw = str(scope.get("severity") or "").strip().lower()
        if sev_raw in {"low", "medium", "high", "critical"}:
            out["severity"] = sev_raw

    return out


def _load_agent_context(db: Session) -> Dict[str, Dict[str, Any]]:
    rows = db.execute(select(AgentModel.agent_id, AgentModel.agent_metadata, AgentModel.tags)).all()
    out: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        aid = str(row.agent_id or "").strip()
        if not aid:
            continue
        meta = row.agent_metadata if isinstance(row.agent_metadata, dict) else {}
        row_tags = row.tags if isinstance(row.tags, list) else []
        meta_tags = meta.get("tags") if isinstance(meta.get("tags"), list) else []
        tags: list[str] = []
        for item in [*row_tags, *meta_tags]:
            v = str(item or "").strip().lower()
            if v and v not in tags:
                tags.append(v)

        hostname = (
            str(meta.get("hostname") or meta.get("host") or meta.get("node_name") or "").strip().lower()
        )
        host_role = (
            str(meta.get("host_role") or meta.get("role") or meta.get("agent_role") or "").strip().lower()
        )
        agent_env = (
            str(meta.get("environment") or meta.get("env") or meta.get("deployment_env") or settings.SEAGULL_ENV or "")
            .strip()
            .lower()
        )
        out[aid] = {
            "agent_hostname": hostname,
            "agent_host_role": host_role,
            "agent_environment": agent_env,
            "agent_tags": tags,
        }
    return out


def _build_rule_context(
    *,
    group_key: Dict[str, Any],
    match: Dict[str, Any],
    rule_id: str,
    severity: str,
    src_ip: Optional[str],
    dst_ip: Optional[str],
    dst_port: Optional[int],
    agent_ctx_map: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    out = dict(group_key or {})
    out.update(
        {
            "rule_id": rule_id,
            "severity": severity,
            "agent_id": (group_key or {}).get("agent_id") or (match or {}).get("agent_id"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": (group_key or {}).get("proto") or (match or {}).get("proto"),
            "event_type": (group_key or {}).get("event_type") or (match or {}).get("event_type"),
            "path_category": (group_key or {}).get("fim_category") or (match or {}).get("extra_path_category"),
            "username": (match or {}).get("extra_username"),
            "target_user": (match or {}).get("extra_target_user"),
            "proc_name": (group_key or {}).get("proc_name") or (match or {}).get("extra_exe_name"),
            "proc_parent_name": (group_key or {}).get("proc_parent_name") or (match or {}).get("extra_parent_exe_name"),
        }
    )

    aid = str(out.get("agent_id") or "").strip()
    if aid and aid in agent_ctx_map:
        meta = agent_ctx_map.get(aid) or {}
        out["agent_hostname"] = meta.get("agent_hostname")
        out["hostname"] = meta.get("agent_hostname")
        out["agent_host_role"] = meta.get("agent_host_role")
        out["host_role"] = meta.get("agent_host_role")
        out["agent_environment"] = meta.get("agent_environment")
        out["environment"] = meta.get("agent_environment")
        out["agent_tags"] = meta.get("agent_tags") or []
    else:
        out["environment"] = str(settings.SEAGULL_ENV or "").strip().lower()

    return out


def _is_tuning_allowlisted(rule: Dict[str, Any], ctx: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    tuning = rule.get("tuning") if isinstance(rule.get("tuning"), dict) else {}
    allowlist = tuning.get("allowlist") if isinstance(tuning, dict) else None
    if isinstance(allowlist, dict) and allowlist and _selector_matches(allowlist, ctx):
        return True, "tuning.allowlist"

    scoped = tuning.get("allowlist_scopes")
    if isinstance(scoped, list):
        for i, item in enumerate(scoped):
            if not isinstance(item, dict):
                continue
            if item.get("enabled") is False:
                continue
            when = item.get("when") if isinstance(item.get("when"), dict) else {}
            if not when or not _selector_matches(when, ctx):
                continue
            reason = str(item.get("reason") or item.get("name") or f"tuning.allowlist_scopes[{i}]").strip()
            return True, reason or "tuning.allowlist_scope"

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
        agent_ctx_map = _load_agent_context(db)

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            if not _schedule_allows(rule, now):
                continue

            rule_id = rule.get("id")
            if not rule_id:
                continue

            rule_type = rule.get("type")
            severity = str(rule.get("severity", "low") or "low").strip().lower()
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

                    sup_ctx = _build_rule_context(
                        group_key=group_key,
                        match=match or {},
                        rule_id=str(rule_id),
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        agent_ctx_map=agent_ctx_map,
                    )
                    eval_cfg = _resolve_tuning_eval(
                        rule,
                        ctx=sup_ctx,
                        base_min_events=min_events,
                        base_condition=condition,
                        base_cooldown_seconds=int(cooldown.total_seconds()),
                        base_severity=severity,
                    )
                    eff_min_events = int(eval_cfg.get("min_events") or 0)
                    eff_condition = eval_cfg.get("condition") if isinstance(eval_cfg.get("condition"), dict) else condition
                    eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
                    eff_severity = str(eval_cfg.get("severity") or severity)
                    sup_ctx["severity"] = eff_severity

                    if eff_min_events and count < eff_min_events:
                        continue
                    if not _evaluate_condition(count, eff_condition):
                        continue

                    last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                    if last_at and eff_cooldown.total_seconds() > 0 and (now - last_at) < eff_cooldown:
                        continue

                    allowlisted, _ = _is_tuning_allowlisted(rule, sup_ctx)
                    if allowlisted:
                        continue

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
                    if eval_cfg.get("applied_scopes"):
                        details["tuning"] = {
                            "applied_scopes": list(eval_cfg.get("applied_scopes") or []),
                            "effective_min_events": eff_min_events,
                            "effective_condition": eff_condition,
                            "effective_cooldown_seconds": int(eff_cooldown.total_seconds()),
                            "effective_severity": eff_severity,
                        }
                    # Mirror to root for easier dashboards (optional but useful)
                    if enrichment.get("src_ips"):
                        details["src_ips"] = enrichment["src_ips"]
                        details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                    if mitre:
                        details["mitre"] = mitre
                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=eff_severity,
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

                    sup_ctx = _build_rule_context(
                        group_key=group_key,
                        match=match or {},
                        rule_id=str(rule_id),
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        agent_ctx_map=agent_ctx_map,
                    )
                    eval_cfg = _resolve_tuning_eval(
                        rule,
                        ctx=sup_ctx,
                        base_min_events=min_events,
                        base_condition=condition,
                        base_cooldown_seconds=int(cooldown.total_seconds()),
                        base_severity=severity,
                    )
                    eff_min_events = int(eval_cfg.get("min_events") or 0)
                    eff_condition = eval_cfg.get("condition") if isinstance(eval_cfg.get("condition"), dict) else condition
                    eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
                    eff_severity = str(eval_cfg.get("severity") or severity)
                    sup_ctx["severity"] = eff_severity

                    if eff_min_events and event_count < eff_min_events:
                        continue
                    if not _evaluate_condition(distinct_count, eff_condition):
                        continue

                    last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                    if last_at and eff_cooldown.total_seconds() > 0 and (now - last_at) < eff_cooldown:
                        continue

                    allowlisted, _ = _is_tuning_allowlisted(rule, sup_ctx)
                    if allowlisted:
                        continue

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
                    if eval_cfg.get("applied_scopes"):
                        details["tuning"] = {
                            "applied_scopes": list(eval_cfg.get("applied_scopes") or []),
                            "effective_min_events": eff_min_events,
                            "effective_condition": eff_condition,
                            "effective_cooldown_seconds": int(eff_cooldown.total_seconds()),
                            "effective_severity": eff_severity,
                        }
                    if enrichment.get("src_ips"):
                        details["src_ips"] = enrichment["src_ips"]
                        details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                    if mitre:
                        details["mitre"] = mitre
                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=eff_severity,
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

                    sup_ctx = _build_rule_context(
                        group_key=group_key,
                        match=match or {},
                        rule_id=str(rule_id),
                        severity=severity,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        agent_ctx_map=agent_ctx_map,
                    )
                    eval_cfg = _resolve_tuning_eval(
                        rule,
                        ctx=sup_ctx,
                        base_min_events=min_events,
                        base_condition=condition,
                        base_cooldown_seconds=int(cooldown.total_seconds()),
                        base_severity=severity,
                    )
                    eff_min_events = int(eval_cfg.get("min_events") or 0)
                    eff_cooldown = timedelta(seconds=max(0, int(eval_cfg.get("cooldown_seconds") or 0)))
                    eff_severity = str(eval_cfg.get("severity") or severity)
                    sup_ctx["severity"] = eff_severity

                    if eff_min_events and event_count < eff_min_events:
                        continue

                    # Evaluate each distinct condition (rule-level for each signal)
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

                    last_at = _recent_alert_last_at(recent_idx, rule_id, src_ip, dst_ip, dst_port)
                    if last_at and eff_cooldown.total_seconds() > 0 and (now - last_at) < eff_cooldown:
                        continue

                    allowlisted, _ = _is_tuning_allowlisted(rule, sup_ctx)
                    if allowlisted:
                        continue

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
                    if eval_cfg.get("applied_scopes"):
                        details["tuning"] = {
                            "applied_scopes": list(eval_cfg.get("applied_scopes") or []),
                            "effective_min_events": eff_min_events,
                            "effective_condition": condition,
                            "effective_cooldown_seconds": int(eff_cooldown.total_seconds()),
                            "effective_severity": eff_severity,
                        }
                    if enrichment.get("src_ips"):
                        details["src_ips"] = enrichment["src_ips"]
                        details["unique_src_ips"] = enrichment.get("unique_src_ips", 0)

                    if mitre:
                        details["mitre"] = mitre
                    alert = AlertModel(
                        rule_id=rule_id,
                        severity=eff_severity,
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
            _, heuristic_alerts = _emit_heuristic_signals(db, now)
            if heuristic_alerts:
                for al in heuristic_alerts:
                    db.add(al)
                created_alerts.extend(heuristic_alerts)
        except Exception:
            pass

        try:
            correlated = _correlate_ddos_incidents(db, now, created_alerts)
            if correlated:
                created_alerts.extend(correlated)
        except Exception:
            pass

        db.commit()
        for alert in created_alerts:
            publish_alert_created_from_row(alert)
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
