from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any, Iterable, List, Mapping, Optional, Sequence

from app.features.alerts.models import AlertModel
from app.features.attack_chain.models import AttackChainCaseModel, AttackChainStepModel
from app.features.detections.domain.scoring import severity_baseline_score
from app.features.correlations.models import EntityBaselineModel
from app.features.correlations.schemas import CorrelationAlertRef, CorrelationEvidenceMatch, CorrelationIncidentOut
from app.features.events.models import NetEventModel
from app.features.exposure.models import ExposureFindingModel
from app.features.vuln.public import VulnFindingDTO


def to_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


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
    alerts_sorted = sorted(alerts, key=lambda a: to_utc_naive(a.created_at))

    segments: List[List[AlertModel]] = []
    cur: List[AlertModel] = [alerts_sorted[0]]
    seg_start = to_utc_naive(alerts_sorted[0].created_at)

    for a in alerts_sorted[1:]:
        dt = (to_utc_naive(a.created_at) - seg_start).total_seconds()
        if dt <= w:
            cur.append(a)
            continue
        segments.append(cur)
        cur = [a]
        seg_start = to_utc_naive(a.created_at)

    if cur:
        segments.append(cur)
    return segments


def segment_records_by_window(rows: Sequence[Any], source: str, dataset: "CorrelationDataset", window_seconds: int) -> List[List[Any]]:
    if not rows:
        return []

    ordered = sorted(rows, key=lambda row: record_timestamp(row, source, dataset))
    start = record_timestamp(ordered[0], source, dataset)
    current: List[Any] = [ordered[0]]
    out: List[List[Any]] = []
    window = max(1, int(window_seconds))

    for row in ordered[1:]:
        ts = record_timestamp(row, source, dataset)
        if (ts - start).total_seconds() <= window:
            current.append(row)
            continue
        out.append(current)
        current = [row]
        start = ts

    if current:
        out.append(current)
    return out


def compute_stage_hits(seg: List[AlertModel], stages: List[dict]) -> dict[str, int]:
    hits: dict[str, int] = {}
    for st in stages or []:
        name = str((st or {}).get("name") or "").strip() or "stage"
        pats = norm_patterns((st or {}).get("patterns") or [])
        if not pats:
            hits[name] = 0
            continue
        hits[name] = sum(1 for a in seg if match_any(a.rule_id, pats))
    return hits


def stage_requirements_met(hits: dict[str, int], stages: List[dict]) -> bool:
    for st in stages or []:
        name = str((st or {}).get("name") or "").strip() or "stage"
        min_count = int((st or {}).get("min_count") or 1)
        if hits.get(name, 0) < max(1, min_count):
            return False
    return True


def alert_ref(a: AlertModel) -> CorrelationAlertRef:
    return CorrelationAlertRef(
        id=a.id,
        created_at=to_utc_naive(a.created_at),
        rule_id=a.rule_id,
        severity=a.severity,
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        dst_port=a.dst_port,
        description=a.description,
    )


def severity_score(value: Any) -> int:
    return severity_baseline_score(value)


def stable_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def deep_get(value: Any, path: str) -> Any:
    current = value
    for raw_part in str(path or "").split("."):
        part = raw_part.strip()
        if not part:
            continue
        if isinstance(current, Mapping):
            current = current.get(part)
            continue
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except Exception:
                return None
            continue
        current = getattr(current, part, None)
    return current


@dataclass
class CorrelationEvidence:
    evidence_type: str
    timestamp: datetime
    alert_id: int | None = None
    net_event_id: int | None = None
    rule_id: str | None = None
    stage: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def signature(self) -> str:
        payload = {
            "evidence_type": self.evidence_type,
            "timestamp": self.timestamp.isoformat(),
            "alert_id": self.alert_id,
            "net_event_id": self.net_event_id,
            "rule_id": self.rule_id,
            "stage": self.stage,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "details": self.details,
        }
        return stable_json(payload)

    def to_schema(self) -> CorrelationEvidenceMatch:
        return CorrelationEvidenceMatch(
            evidence_type=self.evidence_type,
            timestamp=self.timestamp,
            alert_id=self.alert_id,
            net_event_id=self.net_event_id,
            rule_id=self.rule_id,
            stage=self.stage,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            details=dict(self.details or {}),
        )


@dataclass
class CorrelationDataset:
    alerts: list[AlertModel] = field(default_factory=list)
    net_events: list[NetEventModel] = field(default_factory=list)
    vuln_findings: list[VulnFindingDTO] = field(default_factory=list)
    exposure_findings: list[ExposureFindingModel] = field(default_factory=list)
    attack_chain_steps: list[AttackChainStepModel] = field(default_factory=list)
    attack_chain_cases: list[AttackChainCaseModel] = field(default_factory=list)
    entity_states: dict[tuple[str, str], Any] = field(default_factory=dict)
    entity_baseline: dict[str, dict[str, EntityBaselineModel]] | None = None

    @property
    def attack_chain_case_map(self) -> dict[int, AttackChainCaseModel]:
        return {int(case.id): case for case in self.attack_chain_cases if getattr(case, "id", None) is not None}

    def entity_baseline_for(self, entity_type: str | None, entity_value: str | None) -> Any:
        if not entity_type or not entity_value or not self.entity_baseline:
            return None
        by_type = self.entity_baseline.get(str(entity_type))
        if not by_type:
            return None
        return by_type.get(str(entity_value))

    def entity_state_for(self, entity_type: str | None, entity_value: str | None) -> Any:
        if not entity_type or not entity_value:
            return None
        state = self.entity_states.get((str(entity_type), str(entity_value)))
        if state is not None:
            return state
        return self.entity_baseline_for(entity_type, entity_value)


@dataclass
class CorrelationMatch:
    correlation_rule_id: int
    correlation_rule_name: str
    severity: str
    group_by: str
    group_value: str
    started_at: datetime
    ended_at: datetime
    alert_count: int
    unique_rules: list[str] = field(default_factory=list)
    stage_hits: dict[str, int] = field(default_factory=dict)
    entity_type: str | None = None
    entity_value: str | None = None
    risk_score: int | None = None
    confidence: int | None = None
    summary: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    sample_alert_rows: list[AlertModel] = field(default_factory=list)
    evidence_items: list[CorrelationEvidence] = field(default_factory=list)

    def incident_key(self) -> str:
        return f"cr{self.correlation_rule_id}:{self.group_value}:{self.started_at.isoformat()}"

    def to_out(self) -> CorrelationIncidentOut:
        evidence = sorted(self.evidence_items, key=lambda item: item.timestamp, reverse=True)
        sample_alerts = sorted(self.sample_alert_rows, key=lambda row: to_utc_naive(row.created_at), reverse=True)
        return CorrelationIncidentOut(
            id=self.incident_key(),
            correlation_rule_id=self.correlation_rule_id,
            correlation_rule_name=self.correlation_rule_name,
            severity=self.severity,
            group_by=self.group_by,
            group_value=self.group_value,
            entity_type=self.entity_type,
            entity_value=self.entity_value,
            started_at=self.started_at,
            ended_at=self.ended_at,
            alert_count=max(0, int(self.alert_count)),
            unique_rules=sorted({str(rule_id) for rule_id in self.unique_rules if str(rule_id or "").strip()}),
            stage_hits={str(key): int(value) for key, value in dict(self.stage_hits or {}).items()},
            risk_score=self.risk_score,
            confidence=self.confidence,
            summary=self.summary,
            context=dict(self.context or {}),
            sample_alerts=[alert_ref(row) for row in sample_alerts],
            evidence_items=[item.to_schema() for item in evidence],
        )


class BaseCorrelationEngine(ABC):
    strategy_names: tuple[str, ...] = ()

    @abstractmethod
    def build(self, *, rule: Any, dataset: CorrelationDataset, sample_limit: int) -> list[CorrelationMatch]:
        raise NotImplementedError


def select_records(dataset: CorrelationDataset, source: str) -> list[Any]:
    normalized = str(source or "alerts").strip().lower()
    if normalized in {"alerts", "alert"}:
        return list(dataset.alerts)
    if normalized in {"net_events", "net_event", "events", "event"}:
        return list(dataset.net_events)
    if normalized in {"vuln_findings", "vulnerabilities", "vulnerability"}:
        return list(dataset.vuln_findings)
    if normalized in {"exposure_findings", "exposure", "exposures"}:
        return list(dataset.exposure_findings)
    if normalized in {"attack_chain_steps", "attack_steps", "steps"}:
        return list(dataset.attack_chain_steps)
    if normalized in {"attack_chain_cases", "attack_cases", "cases"}:
        return list(dataset.attack_chain_cases)
    return []


def record_timestamp(record: Any, source: str, dataset: CorrelationDataset) -> datetime:
    normalized = str(source or "alerts").strip().lower()
    if normalized in {"alerts", "alert"}:
        return to_utc_naive(record.created_at)
    if normalized in {"net_events", "net_event", "events", "event"}:
        return to_utc_naive(record.timestamp)
    if normalized in {"vuln_findings", "vulnerabilities", "vulnerability"}:
        return to_utc_naive(record.last_seen_at)
    if normalized in {"exposure_findings", "exposure", "exposures"}:
        return to_utc_naive(record.last_seen_at)
    if normalized in {"attack_chain_steps", "attack_steps", "steps"}:
        return to_utc_naive(record.timestamp)
    if normalized in {"attack_chain_cases", "attack_cases", "cases"}:
        return to_utc_naive(record.last_seen_at)
    return datetime.utcnow()


def _mapping_value(mapping: Mapping[str, Any] | None, field: str) -> Any:
    if not isinstance(mapping, Mapping):
        return None
    if field in mapping:
        return mapping.get(field)
    return deep_get(mapping, field)


def extract_alert_value(alert: Any, field: str) -> Any:
    fld = str(field or "").strip()
    if not fld:
        return None
    if fld.startswith("details."):
        return deep_get(getattr(alert, "details", {}) or {}, fld[8:])

    direct = getattr(alert, fld, None)
    if direct is not None:
        return direct

    details = getattr(alert, "details", {}) or {}
    value = _mapping_value(details, fld)
    if value is not None:
        return value

    for bucket in ("group_key", "enrichment", "mitre", "rule_meta"):
        value = _mapping_value(details.get(bucket) if isinstance(details, Mapping) else None, fld)
        if value is not None:
            return value
    return None


def extract_net_event_value(event: Any, field: str) -> Any:
    fld = str(field or "").strip()
    if not fld:
        return None
    if fld.startswith("extra."):
        return deep_get(getattr(event, "extra", {}) or {}, fld[6:])

    direct = getattr(event, fld, None)
    if direct is not None:
        return direct

    extra = getattr(event, "extra", {}) or {}
    value = _mapping_value(extra, fld)
    if value is not None:
        return value
    if fld == "confidence":
        return getattr(event, "heuristic_confidence", None) or _mapping_value(extra, "confidence")
    return None


def extract_vuln_value(finding: Any, field: str) -> Any:
    fld = str(field or "").strip()
    if not fld:
        return None
    if fld.startswith("asset."):
        return deep_get(getattr(finding, "asset", {}) or {}, fld[6:])
    if fld.startswith("evidence."):
        return deep_get(getattr(finding, "evidence", {}) or {}, fld[9:])
    if fld.startswith("details."):
        return deep_get(getattr(finding, "evidence", {}) or {}, fld[8:])
    direct = getattr(finding, fld, None)
    if direct is not None:
        return direct
    if fld == "agent_id":
        return getattr(finding, "asset_agent_id", None)
    return None


def extract_exposure_value(finding: Any, field: str) -> Any:
    fld = str(field or "").strip()
    if not fld:
        return None
    if fld.startswith("extra_data."):
        return deep_get(getattr(finding, "extra_data", {}) or {}, fld[11:])
    if fld.startswith("details."):
        return deep_get(getattr(finding, "extra_data", {}) or {}, fld[8:])
    direct = getattr(finding, fld, None)
    if direct is not None:
        return direct
    return None


def extract_attack_chain_case_value(case: Any, field: str) -> Any:
    fld = str(field or "").strip()
    if not fld:
        return None
    if fld.startswith("context."):
        return deep_get(getattr(case, "context", {}) or {}, fld[8:])
    direct = getattr(case, fld, None)
    if direct is not None:
        return direct
    return _mapping_value(getattr(case, "context", {}) or {}, fld)


def extract_attack_chain_step_value(step: Any, field: str, dataset: CorrelationDataset) -> Any:
    fld = str(field or "").strip()
    if not fld:
        return None
    case = dataset.attack_chain_case_map.get(int(getattr(step, "case_id", 0) or 0))

    if fld.startswith("details."):
        return deep_get(getattr(step, "details", {}) or {}, fld[8:])
    if fld.startswith("case.") and case is not None:
        return extract_attack_chain_case_value(case, fld[5:])

    direct = getattr(step, fld, None)
    if direct is not None:
        return direct

    details = getattr(step, "details", {}) or {}
    value = _mapping_value(details, fld)
    if value is not None:
        return value

    if fld in {"agent_id", "case_agent_id"} and case is not None:
        return getattr(case, "agent_id", None)
    if fld in {"suspect_ip", "case_suspect_ip"} and case is not None:
        return getattr(case, "suspect_ip", None)
    if fld == "max_stage" and case is not None:
        return getattr(case, "max_stage", None)
    if fld == "score" and case is not None:
        return getattr(case, "score", None)
    return None


def extract_source_value(record: Any, field: str, source: str, dataset: CorrelationDataset) -> Any:
    normalized = str(source or "alerts").strip().lower()
    if normalized in {"alerts", "alert"}:
        return extract_alert_value(record, field)
    if normalized in {"net_events", "net_event", "events", "event"}:
        return extract_net_event_value(record, field)
    if normalized in {"vuln_findings", "vulnerabilities", "vulnerability"}:
        return extract_vuln_value(record, field)
    if normalized in {"exposure_findings", "exposure", "exposures"}:
        return extract_exposure_value(record, field)
    if normalized in {"attack_chain_steps", "attack_steps", "steps"}:
        return extract_attack_chain_step_value(record, field, dataset)
    if normalized in {"attack_chain_cases", "attack_cases", "cases"}:
        return extract_attack_chain_case_value(record, field)
    return None


def resolve_entity(rule: Any, record: Any, source: str, dataset: CorrelationDataset) -> tuple[str, str, str, str]:
    entity_cfg = getattr(rule, "entity", None) or {}
    group_label = str(entity_cfg.get("group_by") or getattr(rule, "group_by", "entity") or "entity")
    entity_type = str(entity_cfg.get("type") or group_label or "entity")

    fields = entity_cfg.get("fields")
    if isinstance(fields, list) and fields:
        entity_fields = [str(item) for item in fields if str(item or "").strip()]
    else:
        entity_field = str(entity_cfg.get("field") or "").strip()
        entity_fields = [entity_field] if entity_field else []

    if not entity_fields:
        if str(source or "alerts").strip().lower() in {"alerts", "alert"}:
            fallback = group_value(record, str(getattr(rule, "group_by", "src_ip") or "src_ip"))
            return str(getattr(rule, "group_by", "src_ip") or "src_ip"), fallback, str(getattr(rule, "group_by", "src_ip") or "src_ip"), fallback
        entity_fields = [str(getattr(rule, "group_by", "entity") or "entity")]

    values: list[str] = []
    for field_name in entity_fields:
        raw = extract_source_value(record, field_name, source, dataset)
        text = str(raw or "").strip()
        if not text:
            continue
        values.append(text)

    group_value_text = " | ".join(values) if values else "-"
    return group_label, group_value_text, entity_type, group_value_text


def build_evidence_item(
    *,
    record: Any,
    source: str,
    dataset: CorrelationDataset,
    stage: str | None = None,
    details: dict[str, Any] | None = None,
) -> CorrelationEvidence:
    normalized = str(source or "alerts").strip().lower()
    ts = record_timestamp(record, normalized, dataset)
    payload = dict(details or {})

    if normalized in {"alerts", "alert"}:
        payload.setdefault("description", getattr(record, "description", None))
        payload.setdefault("severity", getattr(record, "severity", None))
        return CorrelationEvidence(
            evidence_type="alert",
            timestamp=ts,
            alert_id=getattr(record, "id", None),
            rule_id=getattr(record, "rule_id", None),
            stage=stage,
            src_ip=getattr(record, "src_ip", None),
            dst_ip=getattr(record, "dst_ip", None),
            dst_port=getattr(record, "dst_port", None),
            details=payload,
        )

    if normalized in {"net_events", "net_event", "events", "event"}:
        payload.setdefault("event_type", getattr(record, "event_type", None))
        payload.setdefault("agent_id", getattr(record, "agent_id", None))
        return CorrelationEvidence(
            evidence_type="net_event",
            timestamp=ts,
            net_event_id=getattr(record, "id", None),
            stage=stage,
            src_ip=getattr(record, "src_ip", None),
            dst_ip=getattr(record, "dst_ip", None),
            dst_port=getattr(record, "dst_port", None),
            details=payload,
        )

    if normalized in {"vuln_findings", "vulnerabilities", "vulnerability"}:
        payload.setdefault("finding_id", getattr(record, "id", None))
        payload.setdefault("asset_key", getattr(record, "asset_key", None))
        payload.setdefault("asset_agent_id", getattr(record, "asset_agent_id", None))
        payload.setdefault("cve", getattr(record, "cve", None))
        payload.setdefault("severity", getattr(record, "severity", None))
        return CorrelationEvidence(
            evidence_type="vulnerability",
            timestamp=ts,
            stage=stage,
            details=payload,
        )

    if normalized in {"exposure_findings", "exposure", "exposures"}:
        payload.setdefault("finding_id", getattr(record, "id", None))
        payload.setdefault("finding_key", getattr(record, "finding_key", None))
        payload.setdefault("asset_key", getattr(record, "asset_key", None))
        payload.setdefault("agent_id", getattr(record, "agent_id", None))
        payload.setdefault("reason_codes", list(getattr(record, "reason_codes", []) or []))
        return CorrelationEvidence(
            evidence_type="exposure_finding",
            timestamp=ts,
            stage=stage,
            details=payload,
        )

    if normalized in {"attack_chain_steps", "attack_steps", "steps"}:
        payload.setdefault("case_id", getattr(record, "case_id", None))
        payload.setdefault("label", getattr(record, "label", None))
        payload.setdefault("kind", extract_attack_chain_step_value(record, "kind", dataset))
        payload.setdefault("technique_id", extract_attack_chain_step_value(record, "technique_id", dataset))
        return CorrelationEvidence(
            evidence_type="attack_chain_step",
            timestamp=ts,
            net_event_id=getattr(record, "event_id", None),
            stage=stage or getattr(record, "stage", None),
            src_ip=getattr(record, "src_ip", None),
            dst_ip=getattr(record, "dst_ip", None),
            dst_port=getattr(record, "dst_port", None),
            details=payload,
        )

    payload.setdefault("case_id", getattr(record, "id", None))
    payload.setdefault("agent_id", getattr(record, "agent_id", None))
    payload.setdefault("suspect_ip", getattr(record, "suspect_ip", None))
    payload.setdefault("score", getattr(record, "score", None))
    payload.setdefault("max_stage", getattr(record, "max_stage", None))
    return CorrelationEvidence(
        evidence_type="attack_chain_case",
        timestamp=ts,
        stage=stage,
        src_ip=getattr(record, "suspect_ip", None),
        details=payload,
    )


def apply_field_filters(record: Any, source: str, dataset: CorrelationDataset, filters: Sequence[dict[str, Any]] | None) -> bool:
    for flt in filters or []:
        field_name = str((flt or {}).get("field") or "").strip()
        operator = str((flt or {}).get("op") or (flt or {}).get("operator") or "eq").strip().lower()
        expected = (flt or {}).get("value")
        actual = extract_source_value(record, field_name, source, dataset)

        if operator == "exists":
            if actual in (None, "", [], {}, ()):
                return False
            continue
        if operator == "truthy":
            if not actual:
                return False
            continue
        if operator == "eq":
            if actual != expected:
                return False
            continue
        if operator == "neq":
            if actual == expected:
                return False
            continue
        if operator == "in":
            if actual not in list(expected or []):
                return False
            continue
        if operator == "contains":
            if isinstance(actual, Sequence) and not isinstance(actual, (str, bytes)):
                if expected not in actual:
                    return False
            elif str(expected or "") not in str(actual or ""):
                return False
            continue
        if operator == "contains_any":
            values = list(expected or [])
            if isinstance(actual, Sequence) and not isinstance(actual, (str, bytes)):
                if not any(item in actual for item in values):
                    return False
            else:
                text = str(actual or "")
                if not any(str(item or "") in text for item in values):
                    return False
            continue
        if operator == "gte":
            if coerce_int(actual, -10**9) < coerce_int(expected, 0):
                return False
            continue
        if operator == "lte":
            if coerce_int(actual, 10**9) > coerce_int(expected, 0):
                return False
            continue
    return True


def filter_records(
    *,
    records: Sequence[Any],
    source: str,
    dataset: CorrelationDataset,
    include_patterns: Sequence[str] | None = None,
    exclude_patterns: Sequence[str] | None = None,
    field_filters: Sequence[dict[str, Any]] | None = None,
) -> list[Any]:
    include = norm_patterns(include_patterns)
    exclude = norm_patterns(exclude_patterns)
    out: list[Any] = []
    for record in records:
        if str(source or "alerts").strip().lower() in {"alerts", "alert"}:
            if not passes_filter(str(getattr(record, "rule_id", "") or ""), include, exclude):
                continue
        if not apply_field_filters(record, source, dataset, field_filters):
            continue
        out.append(record)
    return out


def dedupe_alert_rows(rows: Sequence[AlertModel], sample_limit: int) -> list[AlertModel]:
    seen: set[int] = set()
    out: list[AlertModel] = []
    for row in sorted(rows, key=lambda item: to_utc_naive(item.created_at), reverse=True):
        row_id = getattr(row, "id", None)
        if row_id in seen:
            continue
        if row_id is not None:
            seen.add(int(row_id))
        out.append(row)
        if len(out) >= max(1, int(sample_limit)):
            break
    return list(reversed(out))


def summarize_timedelta_seconds(seconds: int | None) -> str:
    total = max(0, int(seconds or 0))
    if total >= 86400:
        return f"{total // 86400}d"
    if total >= 3600:
        return f"{total // 3600}h"
    if total >= 60:
        return f"{total // 60}m"
    return f"{total}s"
