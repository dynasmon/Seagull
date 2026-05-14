import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Sequence, Set, Tuple

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.cache import get_redis
from app.core.config import settings
from app.core.integrations.clickhouse import (
    clickhouse_events_table_ref,
    clickhouse_is_enabled,
    ensure_clickhouse_events_schema,
    get_clickhouse_client,
)
from app.core.observability import log_event
from app.features.agents.auth import AgentPrincipal
from app.features.alerts.models import AlertModel
from app.features.alerts.realtime import publish_alert_created_from_row
from app.features.events.recent_feed import push_recent_events
from app.features.events.schemas import NetEvent
from app.features.events.service import invalidate_live_event_summary_caches
from app.features.ingest import repository
from app.features.ingest.control.service import (
    bump_ingest_counters,
    enqueue_ingest_message,
    evaluate_backpressure,
    get_storm_status,
    mark_storm_active,
    maybe_flush_stats_to_db,
    record_ingest_quality,
    record_overview_live_drop,
    record_overview_live_telemetry,
    recover_runtime_state,
    storm_maybe_open_alert,
)
from app.features.ingest.storm_control import evaluate_storm, stable_sample
from app.features.network_topology import realtime as topology_realtime
from app.features.realtime.projectors import (
    project_ddos_live_patch,
    project_events_stream_append,
    project_overview_kpi_patch,
    project_storm_status_patch,
)
from app.features.realtime.service import publish_realtime
from app.shared.network.ip_enrichment import attach_ip_context

logger = logging.getLogger("seagull.api.ingest")

# Keep a narrow set of security-critical signals on the hot/Postgres path even
# during storm/backpressure so operator-facing triage views do not go blind.
_HOT_PRIORITY_EVENT_TYPES = {"dos_attack", "ssh_auth"}


def _is_hot_priority_event(event_type: str | None) -> bool:
    return str(event_type or "").strip().lower() in _HOT_PRIORITY_EVENT_TYPES


def _realtime_gate_once(*, key: str, ttl_s: int) -> bool:
    ttl = max(1, int(ttl_s))
    r = get_redis()
    if r is None:
        return True
    try:
        return bool(r.set(str(key), "1", ex=ttl, nx=True))
    except Exception:
        return True


def _build_overview_patch_payload(
    *,
    received: int,
    backlog_events: int,
    backlog_messages: int,
    protection_active: bool,
    phase: str,
    reason: str,
) -> Dict[str, object]:
    return project_overview_kpi_patch(
        received=received,
        backlog_events=backlog_events,
        backlog_messages=backlog_messages,
        protection_active=protection_active,
        phase=phase,
        reason=reason,
    )


def _publish_overview_realtime(
    *,
    received: int,
    backlog_events: int,
    backlog_messages: int,
    protection_active: bool,
    phase: str,
    reason: str,
) -> None:
    patch_payload = _build_overview_patch_payload(
        received=received,
        backlog_events=backlog_events,
        backlog_messages=backlog_messages,
        protection_active=protection_active,
        phase=phase,
        reason=reason,
    )

    if _realtime_gate_once(key="seagull:realtime:overview:patch:1s", ttl_s=1):
        publish_realtime("ui.overview.kpi.patch", patch_payload)

    if _realtime_gate_once(key="seagull:realtime:overview:invalidate:2s", ttl_s=2):
        publish_realtime(
            "ui.overview.invalidate",
            {
                "reason": "ingest_update",
                "phase": str(phase or "ok"),
                "scope": "overview",
            },
        )

    if _realtime_gate_once(key="seagull:realtime:storm:status:1s", ttl_s=1):
        try:
            status_payload = get_storm_status()
        except Exception:
            status_payload = None
        if isinstance(status_payload, dict):
            publish_realtime("ui.overview.storm.patch", project_storm_status_patch(status_payload))


def _build_events_invalidate_payload(*, agent_id: str, events: List[NetEvent]) -> Dict[str, object]:
    domains: set[str] = {"stream", "network", "protocol_intel"}
    event_types: list[str] = []
    high_priority = False

    for event in events:
        event_type = str(event.event_type or "").strip().lower()
        if not event_type:
            continue
        if event_type not in event_types:
            event_types.append(event_type)
        if event_type == "ssh_auth":
            domains.add("ssh")
            high_priority = True
        if event_type in {"dos_attack", "ddos_telemetry"}:
            domains.add("ddos")
            high_priority = True
    return {
        "reason": "ingest_batch",
        "scope": "events",
        "agent_id": str(agent_id or "").strip(),
        "batch_size": int(len(events)),
        "domains": sorted(domains),
        "event_types": event_types[:8],
        "high_priority": bool(high_priority),
    }


def _recent_rows_for_live_stream(rows: List[Dict], *, limit: int) -> List[Dict]:
    ranked = sorted(
        [row for row in rows if isinstance(row, dict)],
        key=lambda row: (str(row.get("timestamp") or ""), str(row.get("agent_id") or ""), str(row.get("event_type") or "")),
        reverse=True,
    )
    return ranked[: max(1, int(limit))]


def _ddos_recent_rows(rows: List[Dict], *, limit: int) -> List[Dict]:
    out: List[Dict] = []
    for row in rows:
        event_type = str((row or {}).get("event_type") or "").strip().lower()
        if event_type not in {"dos_attack", "ddos_telemetry"}:
            continue
        out.append(row)
    out.sort(key=lambda row: str((row or {}).get("timestamp") or ""), reverse=True)
    return out[: max(1, int(limit))]


def _publish_events_realtime(
    *,
    agent_id: str,
    events: List[NetEvent],
    recent_rows: List[Dict],
    live_summary: Dict[str, object] | None,
    pressure: Dict[str, object] | None,
) -> None:
    if not events and not recent_rows:
        return

    invalidate_live_event_summary_caches(agent_id=agent_id)
    if _realtime_gate_once(key="seagull:realtime:events:invalidate:2s", ttl_s=2):
        publish_realtime("ui.events.invalidate", _build_events_invalidate_payload(agent_id=agent_id, events=events))

    if recent_rows and _realtime_gate_once(key="seagull:realtime:events:stream:1s", ttl_s=1):
        invalidate_payload = _build_events_invalidate_payload(agent_id=agent_id, events=events)
        stream_rows = _recent_rows_for_live_stream(recent_rows, limit=24)
        publish_realtime(
            "ui.events.stream.append",
            project_events_stream_append(
                agent_id=agent_id,
                rows=stream_rows,
                batch_size=len(recent_rows),
                coalesced_events=len(stream_rows),
                high_priority=bool(invalidate_payload.get("high_priority")),
                domains=[str(value) for value in (invalidate_payload.get("domains") or [])],
                event_types=[str(value) for value in (invalidate_payload.get("event_types") or [])],
                requires_reconcile=len(stream_rows) < len(recent_rows),
            ),
        )

    _publish_topology_invalidation_for_events(
        agent_id=agent_id,
        events=events,
        recent_rows=recent_rows,
        pressure=pressure,
    )

    ddos_rows = _ddos_recent_rows(recent_rows, limit=18)
    pressure_payload = pressure or {}
    ddos_active = bool(ddos_rows) or bool((pressure_payload or {}).get("active")) or bool((live_summary or {}).get("ddos_samples"))
    if ddos_active and _realtime_gate_once(key="seagull:realtime:ddos:live:1s", ttl_s=1):
        publish_realtime(
            "ui.ddos.live.patch",
            project_ddos_live_patch(
                agent_id=agent_id,
                rows=ddos_rows,
                batch_size=len(recent_rows),
                coalesced_events=len(ddos_rows),
                requires_reconcile=len(ddos_rows) < len(recent_rows),
                summary=live_summary,
                pressure=pressure_payload,
            ),
        )


def _publish_topology_invalidation_for_events(
    *,
    agent_id: str,
    events: List[NetEvent],
    recent_rows: List[Dict],
    pressure: Dict[str, object] | None,
) -> None:
    event_types: list[str] = []
    relevant_count = 0
    for event in events:
        event_type = str(event.event_type or "").strip().lower()
        if event_type and event_type not in event_types:
            event_types.append(event_type)
        if event.src_ip or event.dst_ip:
            relevant_count += 1
    for row in recent_rows:
        if (row or {}).get("src_ip") or (row or {}).get("dst_ip"):
            relevant_count += 1
    if relevant_count <= 0:
        return

    pressure_payload = pressure or {}
    phase = str(pressure_payload.get("phase") or "ok")
    degraded = bool(pressure_payload.get("active")) or phase not in {"ok", "normal"}
    topology_realtime.publish_topology_invalidate(
        reason="event_batch_ingested",
        source="ingest",
        agent_id=str(agent_id or "").strip(),
        batch_size=int(len(events)),
        event_types=event_types,
        degraded=bool(degraded),
        sampled=bool(degraded),
        high_priority=any(t in {"ssh_auth", "dos_attack", "ddos_telemetry"} for t in event_types),
    )


def _degradation_level(*, bp_mode: str, storm_active: bool, backlog_events: int, received: int) -> str:
    soft = max(1, int(settings.SEAGULL_INGEST_BACKPRESSURE_SOFT_BACKLOG_EVENTS or 50000))
    hard = max(soft + 1, int(settings.SEAGULL_INGEST_BACKPRESSURE_HARD_BACKLOG_EVENTS or 200000))
    storm_batch = max(1, int(settings.SEAGULL_INGEST_STORM_MIN_BATCH or 2500))

    if bp_mode == "reject_429" or backlog_events >= hard:
        return "critical"
    if bp_mode == "rollup_only" or backlog_events >= soft or storm_active:
        return "degraded"
    if backlog_events >= max(soft // 2, 1) or received >= storm_batch:
        return "elevated"
    return "normal"


def _target_sample_policy(*, level: str, storm_active: bool) -> tuple[int, int, int, int]:
    warm_pct = max(0, int(settings.SEAGULL_INGEST_WARM_SAMPLE_PERCENT or 0))
    if level == "critical":
        return (
            max(1, int(settings.SEAGULL_INGEST_CRITICAL_HOT_SAMPLE_PERCENT or 1)),
            max(1, int(settings.SEAGULL_INGEST_CRITICAL_CLICKHOUSE_SAMPLE_PERCENT or 10)),
            max(0, int(settings.SEAGULL_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT or 2)),
            max(1, int(settings.SEAGULL_INGEST_RECENT_FEED_MIN_BATCH or 24)),
        )
    if level == "degraded":
        return (
            max(int(settings.SEAGULL_INGEST_STORM_HOT_SAMPLE_PERCENT or 2), int(settings.SEAGULL_INGEST_DEGRADED_HOT_SAMPLE_PERCENT or 5)),
            max(1, int(settings.SEAGULL_INGEST_DEGRADED_CLICKHOUSE_SAMPLE_PERCENT or 25)),
            max(0, int(settings.SEAGULL_INGEST_BACKPRESSURE_WARM_SAMPLE_PERCENT or 2)),
            max(1, int(settings.SEAGULL_INGEST_RECENT_FEED_MIN_BATCH or 24)),
        )
    if level == "elevated":
        # Elevated mode is an advisory early-warning state, not active protection.
        # Keep raw hot telemetry intact here so operators do not see a phantom
        # ~50% drop rate after a storm has already recovered.
        return (
            100,
            max(1, int(settings.SEAGULL_INGEST_CLICKHOUSE_SAMPLE_PERCENT or 100)),
            warm_pct,
            max(8, int(settings.SEAGULL_INGEST_RECENT_FEED_MIN_BATCH or 24) // 2),
        )
    return (100, max(1, int(settings.SEAGULL_INGEST_CLICKHOUSE_SAMPLE_PERCENT or 100)), warm_pct, 12 if storm_active else 8)


def _minimum_indexes(total: int, min_count: int) -> Set[int]:
    if total <= 0 or min_count <= 0:
        return set()
    target = min(total, max(0, int(min_count)))
    if target >= total:
        return set(range(total))
    if target == 1:
        return {0}
    out: Set[int] = set()
    for i in range(target):
        pos = round(i * (total - 1) / max(1, target - 1))
        out.add(int(pos))
    cur = 0
    while len(out) < target:
        out.add(cur)
        cur += 1
    return out


def _ensure_minimum(sampled: Set[int], total: int, min_count: int) -> Set[int]:
    out = set(sampled)
    out.update(_minimum_indexes(total, max(0, int(min_count)) - len(out)))
    return out


def _quality_by_type(
    *,
    event_types_by_idx: List[str],
    hot_selected: Set[int],
    warm_selected: Set[int],
    analytics_selected: Set[int],
) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for idx, ev_type in enumerate(event_types_by_idx):
        key = str(ev_type or "unknown").strip().lower() or "unknown"
        row = out.setdefault(key, {"received": 0, "hot": 0, "warm": 0, "analytics": 0})
        row["received"] += 1
        if idx in hot_selected:
            row["hot"] += 1
        if idx in warm_selected:
            row["warm"] += 1
        if idx in analytics_selected:
            row["analytics"] += 1
    return out


def _row_to_recent_payload(row: Sequence) -> Dict:
    return {
        "agent_id": row[0],
        "event_type": row[1],
        "schema_version": int(row[2] or 1),
        "timestamp": row[3],
        "src_ip": row[4],
        "dst_ip": row[5],
        "src_port": row[6],
        "dst_port": row[7],
        "proto": row[8],
        "bytes": row[9],
        "extra": row[10] if len(row) > 10 and isinstance(row[10], dict) else {},
    }



_DDOS_INLINE_RULES = {
    "udp_amp_flood": {
        "rule_id": "ddos_udp_amp_high_conf_v1",
        "severity": "critical",
        "confidence": 93,
        "description": "DDoS UDP amplification (high confidence)",
        "attack": "ddos",
        "min_confidence": 78,
        "min_unique_src_ips": 12,
        "cooldown_minutes": 3,
        "mitre_tactic": "impact",
        "mitre_technique_id": "T1498.002",
        "mitre_technique": "Network Denial of Service: Reflection Amplification",
    },
    "tcp_syn_flood": {
        "rule_id": "ddos_tcp_syn_high_conf_v1",
        "severity": "critical",
        "confidence": 90,
        "description": "DDoS TCP SYN flood (high confidence)",
        "attack": "ddos",
        "min_confidence": 75,
        "min_unique_src_ips": 10,
        "cooldown_minutes": 3,
        "mitre_tactic": "impact",
        "mitre_technique_id": "T1498.001",
        "mitre_technique": "Network Denial of Service: Direct Network Flood",
    },
    "icmp_flood": {
        "rule_id": "ddos_icmp_flood_high_conf_v1",
        "severity": "high",
        "confidence": 88,
        "description": "DDoS ICMP flood (high confidence)",
        "attack": "ddos",
        "min_confidence": 72,
        "min_unique_src_ips": 8,
        "cooldown_minutes": 4,
        "mitre_tactic": "impact",
        "mitre_technique_id": "T1498.001",
        "mitre_technique": "Network Denial of Service: Direct Network Flood",
    },
    "http_flood": {
        "rule_id": "l7_http_flood_v1",
        "severity": "high",
        "confidence": 87,
        "description": "HTTP flood (L7)",
        "attack": None,
        "min_confidence": 74,
        "min_unique_src_ips": 0,
        "cooldown_minutes": 2,
        "mitre_tactic": "impact",
        "mitre_technique_id": "T1498",
        "mitre_technique": "Network Denial of Service",
    },
    "tls_handshake_flood": {
        "rule_id": "l7_tls_handshake_flood_v1",
        "severity": "high",
        "confidence": 87,
        "description": "TLS handshake flood (L7)",
        "attack": None,
        "min_confidence": 74,
        "min_unique_src_ips": 0,
        "cooldown_minutes": 2,
        "mitre_tactic": "impact",
        "mitre_technique_id": "T1498",
        "mitre_technique": "Network Denial of Service",
    },
}


def _as_int(value: object, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return int(default)
        return int(float(value))
    except Exception:
        return int(default)


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _norm_severity(value: object) -> str:
    sev = str(value or "").strip().lower()
    if sev in {"critical", "high", "medium", "low"}:
        return sev
    return "unknown"


def _is_ddos_summary_event_type(event_type: object) -> bool:
    return str(event_type or "").strip().lower() in {"dos_attack", "ddos_telemetry"}


def _build_live_overview_summary(events: List[NetEvent]) -> Dict[str, object]:
    event_type_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    bytes_sum = 0
    ddos_packets_estimated = 0
    ddos_samples = 0
    ddos_peak_pps = 0.0
    ddos_peak_bps = 0.0
    ddos_peak_syn_ratio = 0.0
    ddos_peak_flow_rps = 0.0

    for e in events:
        ev_type = str(e.event_type or "unknown").strip().lower() or "unknown"
        event_type_counts[ev_type] = int(event_type_counts.get(ev_type) or 0) + 1

        extra = dict(e.extra or {})
        severity = _norm_severity(extra.get("severity"))
        severity_counts[severity] = int(severity_counts.get(severity) or 0) + 1

        bytes_sum += max(0, _as_int(e.bytes, 0))
        is_ddos_event = _is_ddos_summary_event_type(ev_type)

        pps = max(0.0, _as_float(extra.get("pps"), 0.0))
        bps = max(0.0, _as_float(extra.get("bps"), 0.0))
        syn_ratio = max(0.0, _as_float(extra.get("tcp_syn_ratio"), 0.0))
        http_rps = max(0.0, _as_float(extra.get("http_rps"), 0.0))
        tls_hs_rps = max(0.0, _as_float(extra.get("tls_handshake_rps"), 0.0))
        reqs = max(0.0, _as_float(extra.get("requests"), 0.0))
        window_s = max(1.0, _as_float(extra.get("window_seconds"), 1.0))
        flow_rps = max(http_rps, tls_hs_rps, (reqs / window_s))

        if is_ddos_event:
            pkt = max(0, _as_int(extra.get("packets"), 0))
            ddos_packets_estimated += (pkt if pkt > 0 else 1)
            ddos_peak_pps = max(ddos_peak_pps, pps)
            ddos_peak_bps = max(ddos_peak_bps, bps)
            ddos_peak_syn_ratio = max(ddos_peak_syn_ratio, syn_ratio)
            ddos_peak_flow_rps = max(ddos_peak_flow_rps, flow_rps)
            ddos_samples += 1

    return {
        "event_type_counts": event_type_counts,
        "severity_counts": severity_counts,
        "bytes_sum": int(max(0, bytes_sum)),
        "ddos_packets_estimated": int(max(0, ddos_packets_estimated)),
        "ddos_samples": int(max(0, ddos_samples)),
        "ddos_peak_pps": float(max(0.0, ddos_peak_pps)),
        "ddos_peak_bps": float(max(0.0, ddos_peak_bps)),
        "ddos_peak_syn_ratio": float(max(0.0, ddos_peak_syn_ratio)),
        "ddos_peak_flow_rps": float(max(0.0, ddos_peak_flow_rps)),
    }


def _top_src_ip(extra: Dict) -> str | None:
    top = extra.get("top_src") or extra.get("top_sources") or []
    if not isinstance(top, list) or not top:
        return None
    first = top[0] or {}
    if not isinstance(first, dict):
        return None
    ip = first.get("ip") or first.get("src_ip") or first.get("address")
    return str(ip) if ip else None


def _inline_ddos_rule_meta(extra: Dict) -> Dict | None:
    attack = str(extra.get("attack") or "").strip().lower()
    vector = str(extra.get("vector") or "").strip().lower()
    confidence = _as_int(extra.get("confidence"))
    unique_src_ips = _as_int(extra.get("unique_src_ips"))
    distributed = bool(extra.get("distributed"))

    specific = _DDOS_INLINE_RULES.get(vector)
    if specific is not None:
        if specific.get("attack") and attack != str(specific.get("attack")):
            return None
        if confidence < int(specific.get("min_confidence") or 0):
            return None
        if unique_src_ips < int(specific.get("min_unique_src_ips") or 0):
            return None
        return dict(specific)

    if attack == "ddos" and confidence >= 72:
        if distributed and unique_src_ips >= 18:
            return {
                "rule_id": "ddos_distributed_high_cardinality_v1",
                "severity": "high",
                "confidence": 88,
                "description": "Distributed DDoS with high source cardinality",
                "cooldown_minutes": 5,
                "mitre_tactic": "impact",
                "mitre_technique_id": "T1498",
                "mitre_technique": "Network Denial of Service",
            }
        return {
            "rule_id": "ddos_attack_high_conf_v1",
            "severity": "high",
            "confidence": 90,
            "description": "DDoS detected (high confidence)",
            "cooldown_minutes": 2,
            "mitre_tactic": "impact",
            "mitre_technique_id": "T1498",
            "mitre_technique": "Network Denial of Service",
        }

    if attack == "dos" and confidence >= 70 and vector not in {"http_flood", "tls_handshake_flood", "icmp_flood"}:
        return {
            "rule_id": "dos_attack_high_conf_v1",
            "severity": "medium",
            "confidence": 82,
            "description": "DoS detected (high confidence)",
            "cooldown_minutes": 2,
            "mitre_tactic": "impact",
            "mitre_technique_id": "T1498",
            "mitre_technique": "Network Denial of Service",
        }

    return None


def _maybe_create_inline_ddos_alerts(db: Session, *, events: List[NetEvent], now: datetime) -> int:
    candidates: Dict[tuple[str, str, int | None, str | None], Dict] = {}

    for event in events:
        if str(event.event_type or "").strip().lower() != "dos_attack":
            continue
        extra = dict(event.extra or {})
        meta = _inline_ddos_rule_meta(extra)
        if meta is None:
            continue

        dst_ip = str(event.dst_ip or "").strip()
        if not dst_ip:
            continue
        dst_port = int(event.dst_port) if event.dst_port is not None else None
        proto = str(event.proto or "").strip().lower() or None
        rule_id = str(meta.get("rule_id") or "").strip()
        if not rule_id:
            continue

        key = (rule_id, dst_ip, dst_port, proto)
        existing = candidates.get(key)
        confidence = _as_int(extra.get("confidence"), _as_int(meta.get("confidence"), 50))
        pps = _as_float(extra.get("pps"))
        bps = _as_float(extra.get("bps"))
        unique_src_ips = _as_int(extra.get("unique_src_ips"))

        if existing is None or confidence > existing["confidence"] or pps > existing["pps"] or bps > existing["bps"] or unique_src_ips > existing["unique_src_ips"]:
            details = {
                "type": "inline_ingest_ddos",
                "attack": extra.get("attack"),
                "vector": extra.get("vector"),
                "distributed": bool(extra.get("distributed")),
                "severity": extra.get("severity") or meta.get("severity"),
                "confidence": confidence,
                "window_seconds": _as_int(extra.get("window_seconds")),
                "packets": _as_int(extra.get("packets")),
                "requests": _as_int(extra.get("requests")),
                "pps": pps,
                "bps": bps,
                "http_rps": _as_float(extra.get("http_rps")),
                "tls_handshake_rps": _as_float(extra.get("tls_handshake_rps")),
                "tcp_syn_ratio": _as_float(extra.get("tcp_syn_ratio")),
                "unique_src_ips": unique_src_ips,
                "src_entropy_norm": _as_float(extra.get("src_entropy_norm")),
                "top_src_ip": _top_src_ip(extra),
                "proto": proto,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "observed_at": event.timestamp.isoformat() if event.timestamp else now.isoformat(),
                "mitre": {
                    "tactic": meta.get("mitre_tactic"),
                    "technique_id": meta.get("mitre_technique_id"),
                    "technique": meta.get("mitre_technique"),
                    "confidence": _as_int(meta.get("confidence"), confidence),
                },
            }
            candidates[key] = {
                "rule_id": rule_id,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
                "severity": str(meta.get("severity") or "high"),
                "confidence": confidence,
                "description": str(meta.get("description") or "DDoS detected"),
                "mitre_tactic": meta.get("mitre_tactic"),
                "mitre_technique_id": meta.get("mitre_technique_id"),
                "mitre_technique": meta.get("mitre_technique"),
                "cooldown_minutes": max(1, _as_int(meta.get("cooldown_minutes"), 2)),
                "details": details,
                "pps": pps,
                "bps": bps,
                "unique_src_ips": unique_src_ips,
                "src_ip": _top_src_ip(extra),
            }

    if not candidates:
        return 0

    created = 0
    created_rows: List[AlertModel] = []
    for candidate in candidates.values():
        cooldown_since = now - timedelta(minutes=int(candidate["cooldown_minutes"]))
        exists_stmt = (
            select(AlertModel.id)
            .where(
                AlertModel.created_at >= cooldown_since,
                AlertModel.rule_id == candidate["rule_id"],
                AlertModel.dst_ip == candidate["dst_ip"],
            )
            .order_by(AlertModel.created_at.desc())
            .limit(1)
        )
        if candidate["dst_port"] is None:
            exists_stmt = exists_stmt.where(AlertModel.dst_port.is_(None))
        else:
            exists_stmt = exists_stmt.where(AlertModel.dst_port == candidate["dst_port"])
        existing_id = db.execute(exists_stmt).scalar()
        if existing_id is not None:
            continue

        row = AlertModel(
            rule_id=candidate["rule_id"],
            severity=candidate["severity"],
            src_ip=candidate["src_ip"],
            dst_ip=candidate["dst_ip"],
            dst_port=candidate["dst_port"],
            mitre_tactic=candidate["mitre_tactic"],
            mitre_technique_id=candidate["mitre_technique_id"],
            mitre_technique=candidate["mitre_technique"],
            confidence=int(candidate["confidence"]),
            description=candidate["description"],
            details=candidate["details"],
        )
        db.add(row)
        created_rows.append(row)
        created += 1

    if created > 0:
        try:
            db.commit()
            for row in created_rows:
                publish_alert_created_from_row(row)
        except Exception as exc:
            db.rollback()
            log_event(logger, "warning", "inline_ddos_alert_commit_failed", error_type=type(exc).__name__)
            return 0

    return created

def _fallback_direct_insert(db: Session, *, hot_events: List[List], rollup_rows: List[List]) -> int:
    """Fail-open path if Redis is unavailable.

    This keeps the platform usable, but may increase DB pressure under storm.
    """

    repository.persist_fallback_ingest(db, hot_events=hot_events, rollup_rows=rollup_rows)
    return int(len(hot_events))


def _fallback_clickhouse_insert(*, analytics_events: List[List]) -> int:
    if not analytics_events:
        return 0
    if not clickhouse_is_enabled():
        return 0

    try:
        if not ensure_clickhouse_events_schema():
            return 0
        ch = get_clickhouse_client()
        rows = []
        for ev in analytics_events:
            try:
                ts = datetime.fromisoformat(ev[3]) if (len(ev) > 3 and ev[3]) else datetime.now(timezone.utc)
            except Exception:
                ts = datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            extra = ev[10] if (len(ev) > 10 and isinstance(ev[10], dict)) else {}
            rows.append(
                (
                    ts,
                    0,
                    str(ev[0] if len(ev) > 0 else ""),
                    str(ev[1] if len(ev) > 1 else ""),
                    int(ev[2] if len(ev) > 2 and ev[2] is not None else 1),
                    str((extra or {}).get("severity") or "") or None,
                    (str(ev[4]) if len(ev) > 4 and ev[4] else None),
                    (str(ev[5]) if len(ev) > 5 and ev[5] else None),
                    (int(ev[6]) if len(ev) > 6 and ev[6] is not None else None),
                    (int(ev[7]) if len(ev) > 7 and ev[7] is not None else None),
                    (str(ev[8]) if len(ev) > 8 and ev[8] else None),
                    (int(ev[9]) if len(ev) > 9 and ev[9] is not None else None),
                    json.dumps(extra, ensure_ascii=False, separators=(",", ":"), default=str),
                )
            )
        ch.insert(
            clickhouse_events_table_ref(),
            rows,
            column_names=[
                "timestamp",
                "pg_event_id",
                "agent_id",
                "event_type",
                "schema_version",
                "severity",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "proto",
                "bytes",
                "extra_json",
            ],
        )
        return len(rows)
    except Exception as exc:
        log_event(logger, "warning", "ingest_fallback_clickhouse_error", error_type=type(exc).__name__)
        return 0


def storm_status():
    """Storm Mode health payload for the Overview page."""

    return get_storm_status()


def storm_recover(
    *,
    clear_backlog_counters: bool = False,
    clear_ui_caches: bool = True,
):
    """Administrative runtime recovery for post-incident stuck states.

    Clears volatile ingest pressure/storm keys and cache keys so dashboards and
    timelines resume normal update behavior immediately.
    """

    res = recover_runtime_state(
        clear_backlog_counters=bool(clear_backlog_counters),
        clear_ui_caches=bool(clear_ui_caches),
    )
    if not bool(res.get("ok")):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(res.get("reason") or "recover_failed"))
    publish_realtime("ui.overview.invalidate", {"reason": "storm_recover", "scope": "overview"})
    storm_payload = get_storm_status()
    if isinstance(storm_payload, dict):
        publish_realtime("ui.overview.storm.patch", project_storm_status_patch(storm_payload))
    return res


def ingest_events(
    db: Session,
    *,
    events: List[NetEvent],
    agent: AgentPrincipal,
):
    """Ingest network/security events from agents.

    Goals:
    - Survive volumetric attacks without collapsing Postgres.
    - Provide "Storm Mode" sampling + 1-second rollups.
    - Add backpressure using a Redis queue (fast ingest, async persistence).

    Behavior under load:
    - Normal: 100% hot (Postgres), rollups optional.
    - Storm: sample hot + optional warm (Elasticsearch), always rollups.
    - Backpressure: rollup_only or 429 (configurable).
    """

    if not events:
        return {"received": 0, "enqueued": 0}

    max_batch = max(1, int(settings.SEAGULL_INGEST_MAX_BATCH or 10000))
    if len(events) > max_batch:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Too many events in one request (max {max_batch}).",
        )

    # Enforce that an agent can only send its own events.
    for e in events:
        if e.agent_id != agent.agent_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id mismatch")

    live_summary = _build_live_overview_summary(events)
    record_overview_live_telemetry(
        ingest_received=len(events),
        event_type_counts=live_summary.get("event_type_counts") if isinstance(live_summary, dict) else {},
        severity_counts=live_summary.get("severity_counts") if isinstance(live_summary, dict) else {},
        bytes_sum=int(live_summary.get("bytes_sum") or 0),
        ddos_packets_estimated=int(live_summary.get("ddos_packets_estimated") or 0),
        ddos_samples=int(live_summary.get("ddos_samples") or 0),
        ddos_peak_pps=float(live_summary.get("ddos_peak_pps") or 0.0),
        ddos_peak_bps=float(live_summary.get("ddos_peak_bps") or 0.0),
        ddos_peak_syn_ratio=float(live_summary.get("ddos_peak_syn_ratio") or 0.0),
        ddos_peak_flow_rps=float(live_summary.get("ddos_peak_flow_rps") or 0.0),
    )

    # Backpressure decision based on current backlog.
    bp = evaluate_backpressure(received=len(events))

    # Only trust client timestamp if it is close enough to server time.
    max_skew_s = max(0, int(settings.SEAGULL_MAX_EVENT_CLOCK_SKEW_SECONDS or 30))

    now = datetime.now(timezone.utc)
    try:
        _maybe_create_inline_ddos_alerts(db, events=events, now=now)
    except Exception as exc:
        db.rollback()
        log_event(logger, "warning", "inline_ddos_alert_failed", error_type=type(exc).__name__)

    # Storm control (best-effort; fails open).
    # IMPORTANT: "storm" is strictly volumetric (events/sec). Backpressure (queue backlog)
    # is treated separately so the UI can show "DRAINING" once the attack stops.
    decision = evaluate_storm(agent.agent_id, len(events))

    # Final mode
    mode = "normal"
    if bp.mode == "reject_429":
        quality: Dict[str, Dict[str, int]] = {}
        for e in events:
            key = str(e.event_type or "unknown").strip().lower() or "unknown"
            row = quality.setdefault(key, {"received": 0, "hot": 0, "warm": 0, "analytics": 0})
            row["received"] += 1
        record_ingest_quality(breakdown=quality)

        # We intentionally reject early to protect the platform.
        bump_ingest_counters(
            received=len(events),
            hot_kept=0,
            warm_kept=0,
            dropped=0,
            rejected=len(events),
            rollup_only=0,
            storm_active=True,
            sample_hot=0,
            sample_warm=0,
        )
        maybe_flush_stats_to_db()
        mark_storm_active(reason=bp.reason, sample_hot=0, sample_warm=0)
        storm_maybe_open_alert(reason=bp.reason, sample_hot=0, sample_warm=0)
        record_overview_live_drop(dropped_events=len(events))
        _publish_overview_realtime(
            received=len(events),
            backlog_events=int(bp.backlog_events or 0),
            backlog_messages=int(bp.backlog_messages or 0),
            protection_active=True,
            phase="shedding",
            reason=bp.reason,
        )

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Ingest overloaded (backpressure). Please retry.",
            headers={"Retry-After": "2"},
        )

    if bp.mode == "rollup_only":
        mode = "rollup_only"

    storm_active = bool(decision.storm_active)
    pressure_active = mode != "normal"
    active_for_metrics = storm_active or pressure_active
    storm_reason = decision.reason if decision.storm_active else (bp.reason if pressure_active else "ok")
    level = _degradation_level(
        bp_mode=bp.mode,
        storm_active=storm_active,
        backlog_events=int(bp.backlog_events or 0),
        received=len(events),
    )

    rollup_always = bool(settings.SEAGULL_INGEST_ROLLUP_ALWAYS)
    do_rollup = rollup_always or active_for_metrics

    hot_pct, analytics_pct, warm_pct, recent_min_batch = _target_sample_policy(level=level, storm_active=storm_active)
    hot_pct = max(0, min(int(hot_pct), 100))
    analytics_pct = max(1, min(int(analytics_pct), 100))
    warm_pct = max(0, min(int(warm_pct), 100))

    # Normalize to deterministic sample.
    # We only send warm events when ES is enabled AND the event was NOT kept hot.
    warm_enabled = warm_pct > 0 and bool(settings.SEAGULL_INGEST_WARM_ENABLED)

    # Build rollups + sampled event payloads.
    all_rows: List[List] = []
    hot_events: List[List] = []
    analytics_events: List[List] = []
    warm_events: List[List] = []
    rollups: Dict[Tuple, Tuple[int, int]] = {}

    hot_selected: Set[int] = set()
    analytics_selected: Set[int] = set()
    warm_selected: Set[int] = set()
    event_types_by_idx: List[str] = []

    for e in events:
        extra = dict(e.extra or {})
        attach_ip_context(extra, e.src_ip, e.dst_ip)
        hot_priority = _is_hot_priority_event(e.event_type)

        ts = e.timestamp
        use_client_ts = False
        try:
            skew = abs((now - ts).total_seconds())
            use_client_ts = skew <= max_skew_s
            if not use_client_ts:
                extra.setdefault("client_timestamp", ts.isoformat())
                extra.setdefault("clock_skew_seconds", round(skew, 3))
        except Exception:
            use_client_ts = False

        ts_eff = ts if use_client_ts else now

        if do_rollup:
            bucket_ts = ts_eff.replace(microsecond=0)
            k = (
                bucket_ts,
                e.agent_id,
                e.event_type,
                e.dst_ip,
                e.dst_port,
                e.proto,
            )
            prev = rollups.get(k)
            c_prev, b_prev = (prev if prev is not None else (0, 0))
            rollups[k] = (c_prev + 1, b_prev + int(e.bytes or 0))

        seed = "|".join(
            [
                e.agent_id or "",
                e.event_type or "",
                str(ts_eff.replace(microsecond=0).timestamp()),
                e.src_ip or "",
                e.dst_ip or "",
                str(e.src_port or 0),
                str(e.dst_port or 0),
                e.proto or "",
            ]
        )

        keep_hot = hot_priority or stable_sample(seed=seed + "|hot", sample_percent=hot_pct)
        keep_warm = warm_enabled and stable_sample(seed=seed + "|warm", sample_percent=warm_pct)

        row = [
            e.agent_id,
            e.event_type,
            int(getattr(e, "schema_version", 1) or 1),
            ts_eff.isoformat(),
            e.src_ip,
            e.dst_ip,
            e.src_port,
            e.dst_port,
            e.proto,
            e.bytes,
            extra,
        ]

        idx = len(all_rows)
        all_rows.append(row)
        event_types_by_idx.append(str(e.event_type or "unknown").strip().lower() or "unknown")
        if keep_hot:
            hot_selected.add(idx)
        if hot_priority or stable_sample(seed=seed + "|analytics", sample_percent=analytics_pct):
            analytics_selected.add(idx)
        if keep_warm and not keep_hot:
            warm_selected.add(idx)

    hot_selected = _ensure_minimum(
        hot_selected,
        len(all_rows),
        int(settings.SEAGULL_INGEST_MIN_HOT_EVENTS_PER_BATCH or 1) if all_rows else 0,
    )
    analytics_selected = _ensure_minimum(
        analytics_selected,
        len(all_rows),
        int(settings.SEAGULL_INGEST_MIN_CLICKHOUSE_EVENTS_PER_BATCH or 32) if all_rows else 0,
    )
    recent_selected = _ensure_minimum(set(analytics_selected), len(all_rows), int(recent_min_batch or 0))

    for idx, row in enumerate(all_rows):
        if idx in hot_selected:
            hot_events.append(row)
        if idx in analytics_selected:
            analytics_events.append(row)
        if idx in warm_selected and idx not in hot_selected:
            warm_events.append(row)

    quality = _quality_by_type(
        event_types_by_idx=event_types_by_idx,
        hot_selected=hot_selected,
        warm_selected=warm_selected,
        analytics_selected=analytics_selected,
    )
    record_ingest_quality(breakdown=quality)

    hot_kept = len(hot_events)
    warm_kept = len(warm_events)
    analytics_kept = len(analytics_events)

    dropped = max(0, len(events) - hot_kept - warm_kept)

    # Rollup rows for async worker
    rollup_rows = [
        [
            bucket_ts.isoformat(),
            agent_id,
            event_type,
            dst_ip,
            dst_port,
            proto,
            cnt,
            bsum,
        ]
        for (bucket_ts, agent_id, event_type, dst_ip, dst_port, proto), (cnt, bsum) in rollups.items()
    ]

    msg = {
        "v": 1,
        "received_at": now.isoformat(),
        "agent_id": agent.agent_id,
        "mode": mode,
        "degradation_level": level,
        "storm_active": bool(storm_active),
        "storm_reason": storm_reason,
        "sample_hot_percent": hot_pct,
        "sample_analytics_percent": analytics_pct,
        "sample_warm_percent": warm_pct,
        "received": len(events),
        "hot_events": hot_events,
        "analytics_events": analytics_events,
        "warm_events": warm_events,
        "rollups": rollup_rows,
    }

    enqueued = enqueue_ingest_message(message=msg, received=len(events))

    # Redis unavailable: fail open to direct DB insert.
    if not enqueued:
        stored = _fallback_direct_insert(db, hot_events=hot_events, rollup_rows=rollup_rows)
        ch_stored = _fallback_clickhouse_insert(analytics_events=analytics_events)
        recent_feed_rows = [_row_to_recent_payload(all_rows[idx]) for idx in sorted(recent_selected)]
        pushed_recent = push_recent_events(recent_feed_rows) if (stored > 0 or ch_stored > 0) else 0

        bump_ingest_counters(
            received=len(events),
            hot_kept=stored,
            warm_kept=0,
            dropped=len(events) - stored,
            rejected=0,
            rollup_only=1 if mode == "rollup_only" else 0,
            storm_active=active_for_metrics,
            sample_hot=hot_pct,
            sample_warm=warm_pct,
        )
        maybe_flush_stats_to_db()

        if active_for_metrics:
            mark_storm_active(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)
            storm_maybe_open_alert(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)
        _publish_overview_realtime(
            received=len(events),
            backlog_events=int(bp.backlog_events or 0),
            backlog_messages=int(bp.backlog_messages or 0),
            protection_active=bool(active_for_metrics),
            phase="storm" if storm_active else ("draining" if pressure_active else "ok"),
            reason=storm_reason,
        )
        _publish_events_realtime(
            agent_id=agent.agent_id,
            events=events,
            recent_rows=recent_feed_rows if pushed_recent > 0 else [],
            live_summary=live_summary,
            pressure={
                "active": bool(active_for_metrics),
                "protection_active": bool(active_for_metrics),
                "phase": "storm" if storm_active else ("draining" if pressure_active else "ok"),
                "reason": storm_reason,
                "backlog_events": int(bp.backlog_events or 0),
                "backlog_messages": int(bp.backlog_messages or 0),
            },
        )

        return {
            "received": len(events),
            "stored": stored,
            "enqueued": 0,
            "mode": mode,
            "degradation_level": level,
            "storm_active": bool(storm_active),
            "storm_reason": storm_reason,
            "sample_hot_percent": hot_pct,
            "sample_analytics_percent": analytics_pct,
            "sample_warm_percent": warm_pct,
            "analytics_events": analytics_kept,
            "analytics_stored_clickhouse": int(ch_stored),
            "recent_visibility_events": pushed_recent,
            "rollups_written": bool(do_rollup),
            "backpressure": {"mode": bp.mode, "reason": bp.reason, "backlog_events": bp.backlog_events, "backlog_messages": bp.backlog_messages},
            "note": "redis_unavailable_fallback",
        }

    recent_feed_rows = [_row_to_recent_payload(all_rows[idx]) for idx in sorted(recent_selected)]
    pushed_recent = push_recent_events(recent_feed_rows)

    # Update counters for metrics
    bump_ingest_counters(
        received=len(events),
        hot_kept=hot_kept,
        warm_kept=warm_kept,
        dropped=dropped,
        rejected=0,
        rollup_only=1 if mode == "rollup_only" else 0,
        storm_active=active_for_metrics,
        sample_hot=hot_pct,
        sample_warm=warm_pct,
    )
    maybe_flush_stats_to_db()

    # Open/refresh the ingest-shield key and system alert whenever protection is active.
    # This ensures we still alert even if the storm is queue-driven (backpressure).
    if active_for_metrics:
        mark_storm_active(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)
        storm_maybe_open_alert(reason=storm_reason, sample_hot=hot_pct, sample_warm=warm_pct)
    _publish_overview_realtime(
        received=len(events),
        backlog_events=int(bp.backlog_events or 0),
        backlog_messages=int(bp.backlog_messages or 0),
        protection_active=bool(active_for_metrics),
        phase="storm" if storm_active else ("draining" if pressure_active else "ok"),
        reason=storm_reason,
    )
    _publish_events_realtime(
        agent_id=agent.agent_id,
        events=events,
        recent_rows=recent_feed_rows if pushed_recent > 0 else [],
        live_summary=live_summary,
        pressure={
            "active": bool(active_for_metrics),
            "protection_active": bool(active_for_metrics),
            "phase": "storm" if storm_active else ("draining" if pressure_active else "ok"),
            "reason": storm_reason,
            "backlog_events": int(bp.backlog_events or 0),
            "backlog_messages": int(bp.backlog_messages or 0),
        },
    )

    return {
        "received": len(events),
        "enqueued": 1,
        "mode": mode,
        "degradation_level": level,
        "storm_active": bool(storm_active),
        "storm_reason": storm_reason,
        "sample_hot_percent": hot_pct,
        "sample_analytics_percent": analytics_pct,
        "sample_warm_percent": warm_pct,
        "analytics_events": analytics_kept,
        "recent_visibility_events": pushed_recent,
        "rollups_written": bool(do_rollup),
        "backpressure": {"mode": bp.mode, "reason": bp.reason, "backlog_events": bp.backlog_events, "backlog_messages": bp.backlog_messages},
    }
