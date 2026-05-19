from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable

_EPSILON = 1e-9


def finite_float(value: Any, *, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return float(default)
    return number if math.isfinite(number) else float(default)


def clamp_int(value: Any, *, lo: int = 0, hi: int = 100, default: int = 0) -> int:
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        number = int(default)
    return max(int(lo), min(int(hi), int(number)))


@dataclass(frozen=True)
class RunningStats:
    count: int
    mean: float
    m2: float
    minimum: float | None = None
    maximum: float | None = None

    @classmethod
    def empty(cls) -> "RunningStats":
        return cls(count=0, mean=0.0, m2=0.0, minimum=None, maximum=None)

    @classmethod
    def from_state(cls, state: dict[str, Any] | None) -> "RunningStats":
        raw = dict(state or {})
        count = max(0, int(raw.get("count") or 0))
        mean = finite_float(raw.get("mean"), default=0.0)
        m2 = max(0.0, finite_float(raw.get("m2"), default=0.0))
        minimum = raw.get("min")
        maximum = raw.get("max")
        return cls(
            count=count,
            mean=mean,
            m2=m2,
            minimum=(finite_float(minimum) if minimum is not None else None),
            maximum=(finite_float(maximum) if maximum is not None else None),
        )

    def update(self, value: Any) -> "RunningStats":
        x = finite_float(value, default=0.0)
        count = self.count + 1
        delta = x - self.mean
        mean = self.mean + (delta / count)
        delta2 = x - mean
        m2 = max(0.0, self.m2 + (delta * delta2))
        minimum = x if self.minimum is None else min(self.minimum, x)
        maximum = x if self.maximum is None else max(self.maximum, x)
        return RunningStats(count=count, mean=mean, m2=m2, minimum=minimum, maximum=maximum)

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return max(0.0, self.m2 / (self.count - 1))

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def to_state(self) -> dict[str, float | int | None]:
        return {
            "count": int(self.count),
            "mean": finite_float(self.mean),
            "m2": finite_float(self.m2),
            "min": (finite_float(self.minimum) if self.minimum is not None else None),
            "max": (finite_float(self.maximum) if self.maximum is not None else None),
        }


def effective_dispersion(
    *,
    observed_dispersion: Any,
    expected_value: Any,
    minimum: float = 1.0,
) -> float:
    """Return a stable denominator for standardized count-like deviations.

    Stored dispersion remains the actual sample standard deviation. Scoring uses
    a floor so constant or tiny samples do not produce infinite z-scores.
    """

    observed = max(0.0, finite_float(observed_dispersion, default=0.0))
    expected = max(0.0, finite_float(expected_value, default=0.0))
    poisson_floor = math.sqrt(max(expected, 1.0))
    return max(float(minimum), observed, poisson_floor)


def positive_z_score(
    *,
    observed_value: Any,
    expected_value: Any,
    dispersion: Any,
    minimum_dispersion: float = 1.0,
) -> float:
    observed = finite_float(observed_value, default=0.0)
    expected = finite_float(expected_value, default=0.0)
    denom = effective_dispersion(
        observed_dispersion=dispersion,
        expected_value=expected,
        minimum=minimum_dispersion,
    )
    return max(0.0, finite_float((observed - expected) / max(denom, _EPSILON)))


def baseline_confidence(*, sample_count: int, min_samples: int, concentration: float = 0.0) -> int:
    min_samples = max(1, int(min_samples))
    maturity_ratio = min(1.0, max(0.0, float(sample_count) / float(min_samples)))
    concentration = min(1.0, max(0.0, finite_float(concentration, default=0.0)))
    return clamp_int(20 + (60 * maturity_ratio) + (20 * concentration), default=20)


def risk_from_statistical_score(
    *,
    z_score: Any,
    confidence: Any,
    rarity_bits: Any = 0.0,
    floor: int = 0,
) -> int:
    z = min(12.0, max(0.0, finite_float(z_score, default=0.0)))
    rarity = min(12.0, max(0.0, finite_float(rarity_bits, default=0.0)))
    conf = clamp_int(confidence, default=0)
    score = max(int(floor), round((z * 10.0) + (rarity * 5.0) + (conf * 0.35)))
    return clamp_int(score, default=int(floor))


def severity_from_risk(risk_score: Any) -> str:
    score = clamp_int(risk_score, default=0)
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"


def normalized_hour_histogram(raw: Iterable[Any] | None) -> list[int]:
    values = list(raw or [])
    out = [0] * 24
    for hour in range(24):
        try:
            value = int(values[hour]) if hour < len(values) else 0
        except (TypeError, ValueError):
            value = 0
        out[hour] = max(0, value)
    return out


def circular_hour_distance(left: Any, right: Any) -> float:
    left_hour = int(finite_float(left, default=0.0)) % 24
    right_hour = int(finite_float(right, default=0.0)) % 24
    diff = abs(left_hour - right_hour)
    return float(min(diff, 24 - diff))


@dataclass(frozen=True)
class HourHistogramSnapshot:
    counts: list[int]
    sample_count: int
    mode_hour: int
    concentration: float
    dispersion: float


def summarize_hour_histogram(raw: Iterable[Any] | None) -> HourHistogramSnapshot:
    counts = normalized_hour_histogram(raw)
    sample_count = int(sum(counts))
    mode_hour = max(range(24), key=lambda hour: (counts[hour], -hour))
    if sample_count <= 0:
        return HourHistogramSnapshot(
            counts=counts,
            sample_count=0,
            mode_hour=0,
            concentration=0.0,
            dispersion=0.0,
        )
    concentration = counts[mode_hour] / sample_count
    weighted_sq = sum((circular_hour_distance(hour, mode_hour) ** 2) * count for hour, count in enumerate(counts))
    dispersion = math.sqrt(max(0.0, weighted_sq / sample_count))
    return HourHistogramSnapshot(
        counts=counts,
        sample_count=sample_count,
        mode_hour=int(mode_hour),
        concentration=finite_float(concentration),
        dispersion=finite_float(dispersion),
    )


def update_hour_histogram(raw: Iterable[Any] | None, hour: Any) -> HourHistogramSnapshot:
    counts = normalized_hour_histogram(raw)
    counts[int(finite_float(hour, default=0.0)) % 24] += 1
    return summarize_hour_histogram(counts)


def hour_rarity_bits(*, counts: Iterable[Any] | None, hour: Any) -> float:
    normalized = normalized_hour_histogram(counts)
    total = int(sum(normalized))
    observed_count = normalized[int(finite_float(hour, default=0.0)) % 24]
    probability = (observed_count + 1.0) / (total + 24.0)
    return finite_float(-math.log2(max(probability, _EPSILON)))
