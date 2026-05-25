from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.features.ueba.domain.statistics import finite_float, severity_from_risk

PEER_GROUP_DETECTOR_ID = "peer_group_deviation_v1"
PEER_FEATURE_SCHEMA_VERSION = 1
PEER_FEATURE_NAMES: tuple[str, ...] = (
    "proc_exec_rate_mean",
    "proc_exec_rate_stddev",
    "mean_login_hour",
    "distinct_process_names_7d",
    "distinct_ssh_sources_7d",
    "outbound_bytes_mean",
    "outbound_bytes_stddev",
    "fim_events_per_day",
    "lateral_connection_mean",
    "sudo_events_per_day",
)


@dataclass(frozen=True)
class Fingerprint:
    agent_id: str
    values: dict[str, float]


@dataclass(frozen=True)
class NormalizedFingerprints:
    vectors: dict[str, dict[str, float]]
    means: dict[str, float]
    stddevs: dict[str, float]


@dataclass(frozen=True)
class PeerAssignment:
    agent_id: str
    group_id: int
    silhouette_score: float | None
    scoring_enabled: bool


@dataclass(frozen=True)
class PeerGroupStats:
    group_id: int
    centroid: dict[str, float]
    covariance: dict[str, float]
    threshold_distance: float | None
    peer_agents: list[str]
    distances: dict[str, float]


def build_fingerprints(events: list[Any], *, agent_ids: list[str], since: datetime, until: datetime) -> list[Fingerprint]:
    buckets = {str(agent_id): _empty_agent_state(since=since, until=until) for agent_id in agent_ids if agent_id}
    for event in events:
        agent_id = str(getattr(event, "agent_id", "") or "")
        if agent_id not in buckets:
            continue
        state = buckets[agent_id]
        ts = _as_utc(event.timestamp)
        hour_key = ts.replace(minute=0, second=0, microsecond=0)
        day_key = ts.date().isoformat()
        event_type = str(getattr(event, "event_type", "") or "")
        if event_type == "proc_exec":
            state["proc_hour_counts"][hour_key] += 1
            proc_name = str(getattr(event, "proc_name", "") or "")
            if proc_name:
                state["process_names"].add(proc_name)
        elif event_type == "ssh_auth" and str(getattr(event, "ssh_action", "") or "") == "accepted":
            state["login_hours"].append(float(ts.hour + ts.minute / 60.0))
            src_ip = str(getattr(event, "src_ip", "") or "")
            if src_ip:
                state["ssh_sources"].add(src_ip)
        elif event_type in {"flow", "l7_flow", "lateral_conn"}:
            state["outbound_bytes_hour"][hour_key] += max(0, int(getattr(event, "bytes", None) or 0))
        if event_type == "lateral_conn":
            state["lateral_hour_counts"][hour_key] += 1
        elif event_type == "fim_change":
            state["fim_day_counts"][day_key] += 1
        elif event_type == "sudo_cmd":
            state["sudo_day_counts"][day_key] += 1
    return [Fingerprint(agent_id=agent_id, values=_fingerprint_values(state)) for agent_id, state in sorted(buckets.items())]


def normalize_fingerprints(fingerprints: list[Fingerprint]) -> NormalizedFingerprints:
    means: dict[str, float] = {}
    stddevs: dict[str, float] = {}
    for name in PEER_FEATURE_NAMES:
        vals = [finite_float(fp.values.get(name)) for fp in fingerprints]
        mean = sum(vals) / len(vals) if vals else 0.0
        variance = sum((v - mean) ** 2 for v in vals) / max(1, len(vals) - 1) if len(vals) > 1 else 0.0
        stddev = max(math.sqrt(max(0.0, variance)), 1e-6)
        means[name] = finite_float(mean)
        stddevs[name] = finite_float(stddev)
    vectors = {
        fp.agent_id: {
            name: finite_float((finite_float(fp.values.get(name)) - means[name]) / stddevs[name])
            for name in PEER_FEATURE_NAMES
        }
        for fp in fingerprints
    }
    return NormalizedFingerprints(vectors=vectors, means=means, stddevs=stddevs)


def choose_peer_assignments(
    normalized: dict[str, dict[str, float]],
    *,
    min_silhouette_score: float,
    min_agents: int,
) -> list[PeerAssignment]:
    agent_ids = sorted(normalized)
    n = len(agent_ids)
    if n < max(2, int(min_agents)):
        return [PeerAssignment(agent_id=a, group_id=0, silhouette_score=None, scoring_enabled=False) for a in agent_ids]
    best: tuple[float, dict[str, int]] | None = None
    max_k = min(8, max(2, n // 2))
    for k in range(2, max_k + 1):
        labels = _kmeans(normalized, agent_ids=agent_ids, k=k)
        score = _mean_silhouette(normalized, labels)
        if best is None or score > best[0]:
            best = (score, labels)
    if best is None or best[0] < float(min_silhouette_score):
        return [PeerAssignment(agent_id=a, group_id=0, silhouette_score=(best[0] if best else None), scoring_enabled=False) for a in agent_ids]
    score, labels = best
    return [
        PeerAssignment(agent_id=agent_id, group_id=int(labels[agent_id]), silhouette_score=score, scoring_enabled=True)
        for agent_id in agent_ids
    ]


def compute_group_stats(
    normalized: dict[str, dict[str, float]],
    assignments: list[PeerAssignment],
    *,
    distance_percentile: float,
) -> dict[int, PeerGroupStats]:
    grouped: dict[int, list[str]] = defaultdict(list)
    for item in assignments:
        grouped[int(item.group_id)].append(item.agent_id)
    out: dict[int, PeerGroupStats] = {}
    for group_id, agents in grouped.items():
        centroid = {
            name: sum(normalized[a].get(name, 0.0) for a in agents) / len(agents)
            for name in PEER_FEATURE_NAMES
        }
        covariance = {
            name: max(
                1e-6,
                sum((normalized[a].get(name, 0.0) - centroid[name]) ** 2 for a in agents) / max(1, len(agents) - 1),
            )
            for name in PEER_FEATURE_NAMES
        }
        distances = {a: mahalanobis_distance(normalized[a], centroid=centroid, covariance=covariance) for a in agents}
        threshold = percentile(list(distances.values()), distance_percentile) if len(agents) >= 2 else None
        out[group_id] = PeerGroupStats(
            group_id=group_id,
            centroid={k: finite_float(v) for k, v in centroid.items()},
            covariance={k: finite_float(v) for k, v in covariance.items()},
            threshold_distance=(finite_float(threshold) if threshold is not None else None),
            peer_agents=sorted(agents),
            distances=distances,
        )
    return out


def normalize_current_vector(raw: dict[str, float], *, means: dict[str, float], stddevs: dict[str, float]) -> dict[str, float]:
    return {
        name: finite_float((finite_float(raw.get(name)) - finite_float(means.get(name))) / max(1e-6, finite_float(stddevs.get(name), default=1.0)))
        for name in PEER_FEATURE_NAMES
    }


def mahalanobis_distance(
    vector: dict[str, float],
    *,
    centroid: dict[str, float],
    covariance: dict[str, float],
) -> float:
    total = 0.0
    for name in PEER_FEATURE_NAMES:
        delta = finite_float(vector.get(name)) - finite_float(centroid.get(name))
        variance = max(1e-6, finite_float(covariance.get(name), default=1.0))
        total += (delta * delta) / variance
    return finite_float(math.sqrt(max(0.0, total)))


def centroid_delta(vector: dict[str, float], *, centroid: dict[str, float]) -> dict[str, float]:
    return {name: finite_float(vector.get(name)) - finite_float(centroid.get(name)) for name in PEER_FEATURE_NAMES}


def risk_from_peer_distance(distance: float, threshold: float) -> int:
    if threshold <= 0:
        return 0
    ratio = finite_float(distance) / max(1e-6, finite_float(threshold))
    return max(0, min(100, int(round(55 + (ratio - 1.0) * 30))))


def severity_from_peer_distance(distance: float, threshold: float) -> str:
    return severity_from_risk(risk_from_peer_distance(distance, threshold))


def percentile(values: list[float], pct: float) -> float | None:
    clean = sorted(finite_float(v) for v in values if math.isfinite(finite_float(v)))
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0]
    rank = (min(100.0, max(0.0, float(pct))) / 100.0) * (len(clean) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return clean[lo]
    weight = rank - lo
    return clean[lo] * (1 - weight) + clean[hi] * weight


def _empty_agent_state(*, since: datetime, until: datetime) -> dict[str, Any]:
    return {
        "since": _as_utc(since),
        "until": _as_utc(until),
        "proc_hour_counts": defaultdict(int),
        "process_names": set(),
        "login_hours": [],
        "ssh_sources": set(),
        "outbound_bytes_hour": defaultdict(int),
        "fim_day_counts": defaultdict(int),
        "lateral_hour_counts": defaultdict(int),
        "sudo_day_counts": defaultdict(int),
    }


def _fingerprint_values(state: dict[str, Any]) -> dict[str, float]:
    days = max(1.0, (_as_utc(state["until"]) - _as_utc(state["since"])).total_seconds() / 86_400.0)
    proc_hour = list(state["proc_hour_counts"].values())
    outbound_hour = list(state["outbound_bytes_hour"].values())
    lateral_hour = list(state["lateral_hour_counts"].values())
    fim_day = list(state["fim_day_counts"].values())
    sudo_day = list(state["sudo_day_counts"].values())
    return {
        "proc_exec_rate_mean": _mean(proc_hour),
        "proc_exec_rate_stddev": _stddev(proc_hour),
        "mean_login_hour": _mean_circular_hour(state["login_hours"]),
        "distinct_process_names_7d": float(len(state["process_names"])),
        "distinct_ssh_sources_7d": float(len(state["ssh_sources"])),
        "outbound_bytes_mean": _mean(outbound_hour),
        "outbound_bytes_stddev": _stddev(outbound_hour),
        "fim_events_per_day": sum(fim_day) / days if fim_day else 0.0,
        "lateral_connection_mean": _mean(lateral_hour),
        "sudo_events_per_day": sum(sudo_day) / days if sudo_day else 0.0,
    }


def _kmeans(normalized: dict[str, dict[str, float]], *, agent_ids: list[str], k: int) -> dict[str, int]:
    centroids = [dict(normalized[agent_ids[i]]) for i in range(k)]
    labels = {agent_id: 0 for agent_id in agent_ids}
    for _ in range(25):
        changed = False
        for agent_id in agent_ids:
            distances = [_euclidean(normalized[agent_id], centroid) for centroid in centroids]
            label = min(range(k), key=lambda idx: distances[idx])
            changed = changed or labels.get(agent_id) != label
            labels[agent_id] = label
        grouped: dict[int, list[str]] = defaultdict(list)
        for agent_id, label in labels.items():
            grouped[label].append(agent_id)
        for idx in range(k):
            members = grouped.get(idx) or [agent_ids[idx]]
            centroids[idx] = {
                name: sum(normalized[a].get(name, 0.0) for a in members) / len(members)
                for name in PEER_FEATURE_NAMES
            }
        if not changed:
            break
    return labels


def _mean_silhouette(normalized: dict[str, dict[str, float]], labels: dict[str, int]) -> float:
    agent_ids = sorted(normalized)
    grouped: dict[int, list[str]] = defaultdict(list)
    for agent_id, label in labels.items():
        grouped[label].append(agent_id)
    scores: list[float] = []
    for agent_id in agent_ids:
        own = [a for a in grouped[labels[agent_id]] if a != agent_id]
        a = _mean([_euclidean(normalized[agent_id], normalized[other]) for other in own])
        other_means = [
            _mean([_euclidean(normalized[agent_id], normalized[other]) for other in members])
            for label, members in grouped.items()
            if label != labels[agent_id] and members
        ]
        b = min(other_means) if other_means else 0.0
        denom = max(a, b)
        scores.append(0.0 if denom <= 0 else (b - a) / denom)
    return _mean(scores)


def _euclidean(left: dict[str, float], right: dict[str, float]) -> float:
    return math.sqrt(sum((finite_float(left.get(name)) - finite_float(right.get(name))) ** 2 for name in PEER_FEATURE_NAMES))


def _mean(values: list[float]) -> float:
    clean = [finite_float(v) for v in values if math.isfinite(finite_float(v))]
    return sum(clean) / len(clean) if clean else 0.0


def _stddev(values: list[float]) -> float:
    clean = [finite_float(v) for v in values if math.isfinite(finite_float(v))]
    if len(clean) < 2:
        return 0.0
    mean = _mean(clean)
    return math.sqrt(sum((v - mean) ** 2 for v in clean) / (len(clean) - 1))


def _mean_circular_hour(hours: list[float]) -> float:
    if not hours:
        return 0.0
    sin_sum = sum(math.sin((finite_float(h) / 24.0) * math.tau) for h in hours)
    cos_sum = sum(math.cos((finite_float(h) / 24.0) * math.tau) for h in hours)
    angle = math.atan2(sin_sum / len(hours), cos_sum / len(hours))
    if angle < 0:
        angle += math.tau
    return finite_float((angle / math.tau) * 24.0)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = [
    "PEER_FEATURE_NAMES",
    "PEER_FEATURE_SCHEMA_VERSION",
    "PEER_GROUP_DETECTOR_ID",
    "Fingerprint",
    "NormalizedFingerprints",
    "PeerAssignment",
    "PeerGroupStats",
    "build_fingerprints",
    "centroid_delta",
    "choose_peer_assignments",
    "compute_group_stats",
    "mahalanobis_distance",
    "normalize_current_vector",
    "normalize_fingerprints",
    "percentile",
    "risk_from_peer_distance",
    "severity_from_peer_distance",
]
