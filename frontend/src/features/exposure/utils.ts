import { formatInvestigationTimestamp } from "@/shared/components/investigation/utils";

import type {
  EvidenceRef,
  ExposureSeverity,
  ExposureStatus,
  Recommendation,
} from "./types";

export const EXPOSURE_NODE_TYPE_LABELS: Record<string, string> = {
  asset: "Asset",
  service: "Service",
  package: "Package",
  cve: "Vulnerability",
  ip: "Source IP",
  process: "Process",
  file: "File",
  alert: "Alert",
  attack_chain_case: "Attack Chain Case",
  attack_chain_step: "Attack Chain Step",
  investigation: "Investigation",
  response_action: "Response Action",
  protocol: "Protocol",
  identity: "Identity",
};

export const EXPOSURE_EDGE_TYPE_LABELS: Record<string, string> = {
  has_cve: "Asset to vulnerability",
  has_package: "Asset to package",
  has_service: "Asset to service",
  communicates_with: "Network communication",
  executed_process: "Process execution",
  modified_file: "File modification",
  triggered_alert: "Alert evidence",
  part_of_attack_chain: "Attack chain progression",
  part_of_investigation: "Investigation context",
  triggered_response_action: "Operational response",
  lateral_movement_to: "Lateral movement",
  exploited_by: "Exploitation relationship",
};

export const EXPOSURE_EVIDENCE_TYPE_LABELS: Record<string, string> = {
  event: "Event",
  alert: "Alert",
  vulnerability: "Vulnerability",
  attack_chain_case: "Attack Chain Case",
  attack_chain_step: "Attack Chain Step",
  inventory: "Inventory",
  investigation: "Investigation",
  response_action: "Response Action",
};

const SECRET_KEY_PATTERN = /token|secret|password|authorization|cookie|session|credential|private|api[_-]?key/i;

export function exposureSeverityVariant(
  severity: ExposureSeverity | string | null | undefined,
): "critical" | "high" | "medium" | "low" | "info" | "neutral" {
  const normalized = String(severity || "").toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "medium") return "medium";
  if (normalized === "low") return "low";
  if (normalized === "informational") return "info";
  return "neutral";
}

export function exposureStatusVariant(
  status: ExposureStatus | string | null | undefined,
): "active" | "inactive" | "warning" | "danger" | "neutral" {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "active" || normalized === "open" || normalized === "success") return "active";
  if (normalized === "stale" || normalized === "pending" || normalized === "acknowledged") return "warning";
  if (normalized === "inactive" || normalized === "resolved" || normalized === "suppressed") return "inactive";
  if (normalized === "failed" || normalized === "error" || normalized === "cancelled") return "danger";
  return "neutral";
}

export function exposureStatusTone(
  status: ExposureStatus | string | null | undefined,
): "info" | "success" | "warning" | "danger" {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "active" || normalized === "open" || normalized === "created") return "success";
  if (normalized === "stale" || normalized === "pending" || normalized === "acknowledged") return "warning";
  if (normalized === "failed" || normalized === "error" || normalized === "cancelled") return "danger";
  return "info";
}

export function exposureNodeLabel(nodeType: string): string {
  return EXPOSURE_NODE_TYPE_LABELS[nodeType] || toTitleCase(nodeType);
}

export function exposureEdgeLabel(edgeType: string): string {
  return EXPOSURE_EDGE_TYPE_LABELS[edgeType] || toTitleCase(edgeType);
}

export function exposureEvidenceTypeLabel(sourceType: string): string {
  return EXPOSURE_EVIDENCE_TYPE_LABELS[sourceType] || toTitleCase(sourceType);
}

export function formatExposureTimestamp(value: string | number | Date | null | undefined): string {
  return formatInvestigationTimestamp(value);
}

export function formatExposureScore(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-";
  return `${Math.round(value)}`;
}

export function formatExposureConfidence(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-";
  return `${Math.max(0, Math.min(100, Math.round(value)))}%`;
}

export function formatExposureCount(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-";
  return new Intl.NumberFormat("en-US").format(value);
}

export function summarizeEvidenceCounts(
  counts: Record<string, number>,
  opts: { limit?: number } = {},
): string {
  const limit = Math.max(1, opts.limit ?? 3);
  const items = Object.entries(counts || {})
    .filter(([, count]) => typeof count === "number" && count > 0)
    .sort((a, b) => b[1] - a[1]);
  if (items.length === 0) return "No evidence";
  return items
    .slice(0, limit)
    .map(([key, count]) => `${exposureEvidenceTypeLabel(key)} ${count}`)
    .join(" · ");
}

export function totalEvidenceCount(counts: Record<string, number>): number {
  return Object.values(counts || {}).reduce((sum, value) => {
    if (typeof value !== "number" || !Number.isFinite(value)) return sum;
    return sum + value;
  }, 0);
}

export function recommendationPriorityLabel(priority: number): string {
  if (priority <= 1) return "Immediate";
  if (priority <= 2) return "High";
  if (priority <= 3) return "Planned";
  return "Backlog";
}

export function recommendationSafetyLabel(safetyLevel: string): string {
  const normalized = String(safetyLevel || "").toLowerCase();
  if (normalized === "safe") return "Analyst-safe";
  if (normalized === "caution") return "Review before execution";
  if (normalized === "destructive") return "Destructive if executed";
  return toTitleCase(normalized || "unknown");
}

export function sortRecommendations(recommendations: Recommendation[]): Recommendation[] {
  return [...recommendations].sort((a, b) => {
    if (a.priority !== b.priority) return a.priority - b.priority;
    if (a.requires_admin !== b.requires_admin) return a.requires_admin ? 1 : -1;
    return a.title.localeCompare(b.title);
  });
}

export function sanitizeEvidenceMetadata(value: unknown): unknown {
  return sanitizeValue(value, 0);
}

export function boundedMetadataEntries(ref: EvidenceRef): Array<{ key: string; value: unknown }> {
  const metadata = sanitizeEvidenceMetadata(ref.metadata);
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return [];
  return Object.entries(metadata as Record<string, unknown>).slice(0, 8).map(([key, value]) => ({
    key,
    value,
  }));
}

export function truncateText(value: string | null | undefined, max = 140): string {
  const text = String(value || "").trim();
  if (!text) return "";
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

export function toTitleCase(value: string): string {
  return String(value || "")
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(" ");
}

function sanitizeValue(value: unknown, depth: number): unknown {
  if (value === null || value === undefined) return value;
  if (depth >= 3) return "[truncated]";
  if (typeof value === "string") {
    const text = value.trim();
    if (text.length > 280) return `${text.slice(0, 280)}…`;
    if (/^bearer\s+/i.test(text)) return "[redacted]";
    return text;
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.slice(0, 8).map((entry) => sanitizeValue(entry, depth + 1));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>).slice(0, 12)) {
      if (SECRET_KEY_PATTERN.test(key)) {
        out[key] = "[redacted]";
        continue;
      }
      out[key] = sanitizeValue(entry, depth + 1);
    }
    return out;
  }
  return String(value);
}
