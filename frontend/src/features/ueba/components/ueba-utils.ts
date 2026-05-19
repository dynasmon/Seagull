import type { SeverityVariant } from "@/shared/components/SeverityPill";
import type { BadgeVariant } from "@/shared/components/Badge";

import type { UebaBaselineStatus, UebaDetectorStatus, UebaFindingStatus, UebaSeverity } from "../types";

export function severityVariant(severity: UebaSeverity | string): SeverityVariant {
  switch (severity) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    case "informational": return "info";
    default: return "neutral";
  }
}

export function detectorStatusVariant(status: UebaDetectorStatus | string): BadgeVariant {
  switch (status) {
    case "healthy": return "low";
    case "degraded": return "medium";
    case "failing": return "critical";
    case "disabled": return "neutral";
    case "idle": return "neutral";
    default: return "neutral";
  }
}

export function baselineStatusVariant(status: UebaBaselineStatus | string): BadgeVariant {
  switch (status) {
    case "mature": return "low";
    case "warmup": return "medium";
    case "stale": return "neutral";
    default: return "neutral";
  }
}

export function findingStatusVariant(status: UebaFindingStatus | string): BadgeVariant {
  switch (status) {
    case "open": return "medium";
    case "closed": return "neutral";
    case "suppressed": return "neutral";
    default: return "neutral";
  }
}

const REASON_CODE_LABELS: Record<string, string> = {
  rare_login_hour: "Rare login hour",
  login_hour_far_from_baseline: "Login hour far from baseline",
  ssh_source_diversity_above_baseline: "Unusual number of source IPs",
  high_z_score: "Statistical outlier (high z-score)",
  low_probability: "Low probability event",
};

export function reasonCodeLabel(code: string): string {
  return REASON_CODE_LABELS[code] ?? code.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const DETECTOR_LABELS: Record<string, string> = {
  ssh_login_hour_v1: "SSH Login Hour",
  ssh_source_diversity_v1: "SSH Source Diversity",
};

export function detectorLabel(detectorId: string): string {
  return DETECTOR_LABELS[detectorId] ?? detectorId;
}

const METRIC_LABELS: Record<string, string> = {
  login_hour: "Login Hour",
  distinct_successful_source_ips: "Distinct Source IPs",
};

export function metricLabel(metricName: string): string {
  return METRIC_LABELS[metricName] ?? metricName.replace(/_/g, " ");
}

export function formatFloat(value: number | null | undefined, decimals = 2): string {
  if (value == null) return "—";
  return value.toFixed(decimals);
}

export function formatConfidence(confidence: number): string {
  return `${confidence}%`;
}

export function formatRiskScore(score: number): string {
  return String(score);
}

export function formatDeviation(
  observed: number | null,
  expected: number | null,
  metricName: string,
): string {
  if (observed == null && expected == null) return "—";
  const obs = observed != null ? formatMetricValue(observed, metricName) : "?";
  const exp = expected != null ? formatMetricValue(expected, metricName) : "?";
  return `${obs} (exp. ${exp})`;
}

function formatMetricValue(value: number, metricName: string): string {
  if (metricName === "login_hour") {
    const h = Math.round(value) % 24;
    return `${String(h).padStart(2, "0")}:00 UTC`;
  }
  return value % 1 === 0 ? String(value) : value.toFixed(2);
}

export function formatExplanationEntries(
  explanation: Record<string, unknown>,
  _metricName: string,
): Array<{ key: string; value: string }> {
  const EXCLUDED = new Set(["method", "hour_counts"]);

  const LABELS: Record<string, string> = {
    expected_hour_utc: "Expected hour (UTC)",
    observed_hour_utc: "Observed hour (UTC)",
    hour_distance: "Hour distance",
    rarity_bits: "Rarity (bits)",
    z_score: "Z-score",
    sample_count: "Baseline samples",
    window_minutes: "Window (min)",
    expected_distinct_sources: "Expected distinct sources",
    observed_distinct_sources: "Observed distinct sources",
    sample_stddev: "Baseline std dev",
    effective_dispersion: "Effective dispersion",
    event_count: "Event count",
  };

  return Object.entries(explanation)
    .filter(([k, v]) => !EXCLUDED.has(k) && v != null)
    .map(([k, v]) => {
      const label = LABELS[k] ?? k.replace(/_/g, " ");
      let display = "";
      if (typeof v === "number") {
        if (k === "expected_hour_utc" || k === "observed_hour_utc") {
          const h = Math.round(v) % 24;
          display = `${String(h).padStart(2, "0")}:00 UTC`;
        } else {
          display = v % 1 === 0 ? String(v) : v.toFixed(3);
        }
      } else {
        display = String(v);
      }
      return { key: label, value: display };
    });
}

export function baselineMaturityPercent(sampleCount: number, minSamples: number): number {
  if (minSamples <= 0) return 100;
  return Math.min(100, Math.round((sampleCount / minSamples) * 100));
}

export function relativeTime(isoString: string | null): string {
  if (!isoString) return "—";
  const ms = Date.now() - new Date(isoString).getTime();
  const s = Math.floor(ms / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export function formatTimestamp(isoString: string | null): string {
  if (!isoString) return "—";
  const d = new Date(isoString);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}
