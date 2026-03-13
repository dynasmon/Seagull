from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Dict, Iterable, List, Optional

from app.models.alerts import AlertModel
from app.schemas.correlations import CorrelationAlertRef, CorrelationIncidentOut


def norm_patterns(v: Optional[Iterable[str]]) -> List[str]:
    if not v:
        return []
    out: List[str] = []
    seen = set()
    for raw in v:
        s = str(raw or "").strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def match_any(rule_id: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    rid = str(rule_id or "")
    for p in patterns:
        if fnmatchcase(rid.lower(), p.lower()):
            return True
    return False


def passes_filter(rule_id: str, include: List[str], exclude: List[str]) -> bool:
    if exclude and match_any(rule_id, exclude):
        return False
    if not include:
        return True
    return match_any(rule_id, include)


def group_value(alert: AlertModel, group_by: str) -> str:
    g = (group_by or "").lower().strip()
    src = alert.src_ip or "-"
    dst = alert.dst_ip or "-"
    port = str(alert.dst_port) if alert.dst_port is not None else "-"

    if g in ("src", "src_ip", "source"):
        return src
    if g in ("dst", "dst_ip", "destination"):
        return dst
    if g in ("dst_port", "port"):
        return port
    if g in ("src_dst", "src+dst", "pair"):
        return f"{src}→{dst}"
    if g in ("src_dst_port", "tuple"):
        return f"{src}→{dst}:{port}"
    return "all"


def segment_by_window(alerts: List[AlertModel], window_seconds: int) -> List[List[AlertModel]]:
    if not alerts:
        return []

    w = max(1, int(window_seconds))
    alerts_sorted = sorted(alerts, key=lambda a: a.created_at)

    segments: List[List[AlertModel]] = []
    cur: List[AlertModel] = [alerts_sorted[0]]
    seg_start = alerts_sorted[0].created_at

    for a in alerts_sorted[1:]:
        dt = (a.created_at - seg_start).total_seconds()
        if dt <= w:
            cur.append(a)
            continue
        segments.append(cur)
        cur = [a]
        seg_start = a.created_at

    if cur:
        segments.append(cur)
    return segments


def compute_stage_hits(seg: List[AlertModel], stages: List[dict]) -> Dict[str, int]:
    hits: Dict[str, int] = {}
    for st in stages or []:
        name = str((st or {}).get("name") or "").strip() or "stage"
        pats = norm_patterns((st or {}).get("patterns") or [])
        if not pats:
            hits[name] = 0
            continue
        hits[name] = sum(1 for a in seg if match_any(a.rule_id, pats))
    return hits


def stage_requirements_met(hits: Dict[str, int], stages: List[dict]) -> bool:
    for st in stages or []:
        name = str((st or {}).get("name") or "").strip() or "stage"
        min_count = int((st or {}).get("min_count") or 1)
        if hits.get(name, 0) < max(1, min_count):
            return False
    return True


def alert_ref(a: AlertModel) -> CorrelationAlertRef:
    return CorrelationAlertRef(
        id=a.id,
        created_at=a.created_at,
        rule_id=a.rule_id,
        severity=a.severity,
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        dst_port=a.dst_port,
        description=a.description,
    )


def build_incidents(rules: list, alerts: List[AlertModel], sample_limit: int) -> List[CorrelationIncidentOut]:
    incidents: List[CorrelationIncidentOut] = []

    for r in rules:
        include = norm_patterns(getattr(r, "include_patterns", None) or [])
        exclude = norm_patterns(getattr(r, "exclude_patterns", None) or [])
        strategy = str(getattr(r, "strategy", "burst") or "burst").lower()
        group_by = str(getattr(r, "group_by", "src_ip") or "src_ip")
        window_seconds = int(getattr(r, "window_seconds", 600) or 600)
        min_alerts = int(getattr(r, "min_alerts", 2) or 2)
        stages = list(getattr(r, "stages", None) or [])

        grouped: Dict[str, List[AlertModel]] = {}
        for a in alerts:
            if not passes_filter(a.rule_id, include, exclude):
                continue
            gv = group_value(a, group_by)
            grouped.setdefault(gv, []).append(a)

        for gv, rows in grouped.items():
            segments = segment_by_window(rows, window_seconds)
            for seg in segments:
                if not seg or len(seg) < min_alerts:
                    continue

                stage_hits = compute_stage_hits(seg, stages) if strategy == "chain" else {}
                if strategy == "chain" and not stage_requirements_met(stage_hits, stages):
                    continue

                start = min(a.created_at for a in seg)
                end = max(a.created_at for a in seg)
                unique_rules = sorted({a.rule_id for a in seg})
                incident_id = f"cr{r.id}:{gv}:{start.isoformat()}"
                sample = sorted(seg, key=lambda a: a.created_at, reverse=True)[: max(1, int(sample_limit))]

                incidents.append(
                    CorrelationIncidentOut(
                        id=incident_id,
                        correlation_rule_id=r.id,
                        correlation_rule_name=r.name,
                        severity=r.severity,
                        group_by=group_by,
                        group_value=gv,
                        started_at=start,
                        ended_at=end,
                        alert_count=len(seg),
                        unique_rules=unique_rules,
                        stage_hits=stage_hits,
                        sample_alerts=[alert_ref(x) for x in sample],
                    )
                )

    incidents.sort(key=lambda x: x.started_at, reverse=True)
    return incidents
