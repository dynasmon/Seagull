import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.features.alerts.models import AlertModel
from app.features.events.worker_runtime import NetEventModel
from app.shared.taxonomy.catalog import technique_name

from .conditions import (
    _as_int,
    _extra_flow_direction,
    _extra_indicator_host,
    _host_suspicion_reason,
    _is_unusual_app_protocol_use,
    _netevent_exists_recent,
)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _build_beacon_candidates(rows: List[Any], now: datetime) -> List[Dict[str, Any]]:
    now = _as_utc(now)
    win_s = max(300, int(settings.SEAGULL_HEUR_BEACON_WINDOW_SECONDS or 3600))
    min_events = max(4, int(settings.SEAGULL_HEUR_BEACON_MIN_EVENTS or 7))
    min_interval = max(2.0, float(settings.SEAGULL_HEUR_BEACON_MIN_INTERVAL_SECONDS or 8))
    max_interval = max(min_interval, float(settings.SEAGULL_HEUR_BEACON_MAX_INTERVAL_SECONDS or 900))
    max_jitter = max(0.01, min(1.0, float(settings.SEAGULL_HEUR_BEACON_MAX_JITTER or 0.22)))

    since = now - timedelta(seconds=win_s)

    groups: Dict[Tuple[str, str, int, str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        if _as_utc(r.timestamp) < since:
            continue
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
                "timestamp": _as_utc(r.timestamp),
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


def _build_exfil_candidates(rows: List[Any], now: datetime) -> List[Dict[str, Any]]:
    now = _as_utc(now)
    baseline_s = max(3600, int(settings.SEAGULL_HEUR_EXFIL_BASELINE_SECONDS or 86400))
    recent_s = max(120, int(settings.SEAGULL_HEUR_EXFIL_WINDOW_SECONDS or 600))
    min_events = max(4, int(settings.SEAGULL_HEUR_EXFIL_MIN_EVENTS or 8))
    min_recent_bytes = max(1024 * 1024, int(settings.SEAGULL_HEUR_EXFIL_MIN_BYTES or 8 * 1024 * 1024))
    spike_factor = max(1.0, float(settings.SEAGULL_HEUR_EXFIL_SPIKE_FACTOR or 3.0))
    rare_baseline_events = max(1, int(settings.SEAGULL_HEUR_EXFIL_RARE_BASELINE_EVENTS or 5))

    since = now - timedelta(seconds=baseline_s)
    recent_since = now - timedelta(seconds=recent_s)

    groups: Dict[Tuple[str, str, int, str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        if _as_utc(r.timestamp) < since:
            continue
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
                "timestamp": _as_utc(r.timestamp),
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
    now = _as_utc(now)
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


def _build_egress_anomaly_candidates(db: Session, rows: List[Any], now: datetime) -> List[Dict[str, Any]]:
    now = _as_utc(now)
    baseline_s = max(1800, int(settings.SEAGULL_HEUR_EGRESS_BASELINE_SECONDS or 21600))
    recent_s = max(120, int(settings.SEAGULL_HEUR_EGRESS_WINDOW_SECONDS or 900))
    min_events = max(3, int(settings.SEAGULL_HEUR_EGRESS_MIN_EVENTS or 5))
    min_recent_bytes = max(256 * 1024, int(settings.SEAGULL_HEUR_EGRESS_MIN_BYTES or 2 * 1024 * 1024))
    spike_factor = max(1.0, float(settings.SEAGULL_HEUR_EGRESS_SPIKE_FACTOR or 2.5))
    rare_baseline_events = max(1, int(settings.SEAGULL_HEUR_EGRESS_RARE_BASELINE_EVENTS or 3))
    correlation_s = max(120, int(settings.SEAGULL_HEUR_EGRESS_CORRELATION_SECONDS or 900))

    since = now - timedelta(seconds=baseline_s)
    recent_since = now - timedelta(seconds=recent_s)

    groups: Dict[Tuple[str, str, int, str, str, str], List[Dict[str, Any]]] = {}
    for r in rows:
        if _as_utc(r.timestamp) < since:
            continue
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
                "timestamp": _as_utc(r.timestamp),
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


def _fetch_shared_flow_rows(db: Session, now: datetime) -> List[Any]:
    max_rows = max(1000, int(settings.SEAGULL_HEUR_MAX_ROWS or 50000))
    beacon_win_s = max(300, int(settings.SEAGULL_HEUR_BEACON_WINDOW_SECONDS or 3600))
    exfil_baseline_s = max(3600, int(settings.SEAGULL_HEUR_EXFIL_BASELINE_SECONDS or 86400))
    egress_baseline_s = max(1800, int(settings.SEAGULL_HEUR_EGRESS_BASELINE_SECONDS or 21600))
    max_window_s = max(beacon_win_s, exfil_baseline_s, egress_baseline_s)
    since = now - timedelta(seconds=max_window_s)
    return db.execute(
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


def _emit_heuristic_signals(db: Session, now: datetime) -> Tuple[List[NetEventModel], List[AlertModel]]:
    now = _as_utc(now)
    derived_events: List[NetEventModel] = []
    derived_alerts: List[AlertModel] = []
    beacon_cd = max(120, int(settings.SEAGULL_HEUR_BEACON_COOLDOWN_SECONDS or 900))
    exfil_cd = max(120, int(settings.SEAGULL_HEUR_EXFIL_COOLDOWN_SECONDS or 1200))
    egress_cd = max(120, int(settings.SEAGULL_HEUR_EGRESS_COOLDOWN_SECONDS or 1200))

    shared_rows = _fetch_shared_flow_rows(db, now)

    for cand in _build_beacon_candidates(shared_rows, now):
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

    for cand in _build_exfil_candidates(shared_rows, now):
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

    for cand in _build_egress_anomaly_candidates(db, shared_rows, now):
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
