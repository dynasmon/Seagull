import type { MetricTone } from "@/shared/components/MetricCard";

export type RangePreset = {
  id: string;
  label: string;
  seconds: number;
};

export const RANGE_PRESETS: RangePreset[] = [
  { id: "15m", label: "15m", seconds: 15 * 60 },
  { id: "1h", label: "1h", seconds: 60 * 60 },
  { id: "6h", label: "6h", seconds: 6 * 60 * 60 },
  { id: "24h", label: "24h", seconds: 24 * 60 * 60 },
];

export const DEFAULT_RANGE_PRESET_ID = "1h";

export function resolveRangePreset(id: string): RangePreset {
  return RANGE_PRESETS.find((p) => p.id === id) ?? RANGE_PRESETS[1];
}

export type StatSpec = {
  key: string;
  label: string;
  unit: string;
  tone?: (value: number | null) => MetricTone;
};

const activeTone = (value: number | null): MetricTone => (value !== null && value >= 0.5 ? "warning" : "success");

export const STAT_BAND: StatSpec[] = [
  { key: "workers_up", label: "Workers up", unit: "count", tone: (v) => (v !== null && v > 0 ? "success" : "warning") },
  { key: "ingest_events_received_rate", label: "Events received", unit: "ops" },
  { key: "ingest_queue_depth", label: "Queue depth", unit: "count", tone: (v) => (v !== null && v > 50000 ? "warning" : "default") },
  { key: "ingest_backpressure_active", label: "Backpressure", unit: "bool", tone: activeTone },
  { key: "ingest_storm_active", label: "Storm", unit: "bool", tone: activeTone },
  { key: "http_request_rate", label: "HTTP req", unit: "ops" },
  { key: "http_error_ratio", label: "HTTP 5xx", unit: "ratio", tone: (v) => (v !== null && v > 0 ? "danger" : "success") },
  { key: "http_latency_p95_ms", label: "HTTP p95", unit: "ms" },
  { key: "detection_cycle_rate", label: "Detection cycles", unit: "ops" },
  { key: "alert_created_rate", label: "Alerts", unit: "ops", tone: (v) => (v !== null && v > 0 ? "info" : "default") },
];

export type ChartKeySpec = {
  key: string;
  label: string;
};

export type ChartPanelSpec = {
  id: string;
  title: string;
  unit: string;
  keys: ChartKeySpec[];
  variant?: "line" | "area";
  stacked?: boolean;
};

export type SectionAccent = "primary" | "info" | "warning" | "danger" | "success";

export type ObservabilitySection = {
  id: string;
  title: string;
  description: string;
  accent: SectionAccent;
  panels: ChartPanelSpec[];
};

export const SECTIONS: ObservabilitySection[] = [
  {
    id: "http",
    title: "HTTP surface",
    accent: "primary",
    description: "Request throughput, latency, and error posture across the backend API.",
    panels: [
      {
        id: "http_throughput",
        title: "Request rate",
        unit: "ops",
        variant: "area",
        keys: [{ key: "http_request_rate", label: "requests" }],
      },
      {
        id: "http_latency",
        title: "Latency p95 / p99",
        unit: "ms",
        variant: "line",
        keys: [
          { key: "http_latency_p95_ms", label: "p95" },
          { key: "http_latency_p99_ms", label: "p99" },
        ],
      },
      {
        id: "http_errors",
        title: "5xx ratio",
        unit: "ratio",
        variant: "area",
        keys: [{ key: "http_error_ratio", label: "5xx ratio" }],
      },
    ],
  },
  {
    id: "ingest",
    title: "Ingest pipeline",
    accent: "info",
    description: "Event flow from receive to processing, hot-path latency, and backpressure state.",
    panels: [
      {
        id: "ingest_flow",
        title: "Event flow",
        unit: "ops",
        variant: "line",
        keys: [
          { key: "ingest_events_received_rate", label: "received" },
          { key: "ingest_events_processed_rate", label: "processed" },
          { key: "ingest_events_sampled_rate", label: "shed" },
        ],
      },
      {
        id: "ingest_latency",
        title: "Hot-path p95",
        unit: "seconds",
        variant: "area",
        keys: [{ key: "ingest_hot_path_p95_seconds", label: "p95" }],
      },
      {
        id: "ingest_queue",
        title: "Queue depth",
        unit: "count",
        variant: "area",
        keys: [{ key: "ingest_queue_depth", label: "depth" }],
      },
      {
        id: "ingest_pressure",
        title: "Pressure state",
        unit: "bool",
        variant: "area",
        keys: [
          { key: "ingest_backpressure_active", label: "backpressure" },
          { key: "ingest_storm_active", label: "storm" },
        ],
      },
    ],
  },
  {
    id: "detection",
    title: "Detection engine",
    accent: "warning",
    description: "Rule-evaluation cycles, per-cycle latency, and rule match / error volume.",
    panels: [
      {
        id: "detection_cycles",
        title: "Cycle rate",
        unit: "ops",
        variant: "area",
        keys: [{ key: "detection_cycle_rate", label: "cycles" }],
      },
      {
        id: "detection_latency",
        title: "Cycle p95",
        unit: "seconds",
        variant: "area",
        keys: [{ key: "detection_cycle_p95_seconds", label: "p95" }],
      },
      {
        id: "detection_rules",
        title: "Rule activity",
        unit: "ops",
        variant: "line",
        keys: [
          { key: "detection_rule_eval_rate", label: "evaluations" },
          { key: "detection_rule_match_rate", label: "matches" },
          { key: "detection_rule_error_rate", label: "errors" },
        ],
      },
    ],
  },
  {
    id: "alerts",
    title: "Alert generation",
    accent: "danger",
    description: "Alert creation rate across detectors and its severity breakdown.",
    panels: [
      {
        id: "alerts_rate",
        title: "Alerts created",
        unit: "ops",
        variant: "area",
        keys: [{ key: "alert_created_rate", label: "alerts" }],
      },
      {
        id: "alerts_by_severity",
        title: "By severity",
        unit: "ops",
        variant: "area",
        stacked: true,
        keys: [{ key: "alert_created_rate_by_severity", label: "alerts" }],
      },
    ],
  },
  {
    id: "workers",
    title: "Worker fleet",
    accent: "success",
    description: "Running worker children by group and their start / exit churn.",
    panels: [
      {
        id: "workers_by_group",
        title: "Running by group",
        unit: "count",
        variant: "area",
        stacked: true,
        keys: [{ key: "workers_up_by_group", label: "workers" }],
      },
      {
        id: "worker_starts",
        title: "Start rate",
        unit: "ops",
        variant: "line",
        keys: [{ key: "worker_start_rate", label: "starts" }],
      },
      {
        id: "worker_exits",
        title: "Exits by outcome",
        unit: "ops",
        variant: "line",
        keys: [{ key: "worker_exit_rate_by_outcome", label: "exits" }],
      },
    ],
  },
];

export function collectRangeKeys(): string[] {
  const keys = new Set<string>();
  for (const stat of STAT_BAND) keys.add(stat.key);
  for (const section of SECTIONS) {
    for (const panel of section.panels) {
      for (const spec of panel.keys) keys.add(spec.key);
    }
  }
  return Array.from(keys);
}
