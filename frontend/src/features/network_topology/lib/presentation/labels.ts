import type { BadgeVariant } from "@/shared/components/Badge";
import { labelForIpScope } from "@/shared/lib/ipClassification";

import type { TopologySeverity } from "../../types";

export function toTitleLabel(value: string | null | undefined): string {
  const raw = String(value ?? "").trim();
  if (!raw) return "Unknown";
  return raw
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function compactNumber(value: number | null | undefined): string {
  const n = Number(value ?? 0);
  if (!Number.isFinite(n)) return "0";
  return new Intl.NumberFormat(undefined, { notation: n >= 10000 ? "compact" : "standard" }).format(n);
}

export function formatTopologyTimestamp(value: string | null | undefined): string {
  const ts = Date.parse(String(value ?? ""));
  if (!Number.isFinite(ts)) return "-";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(ts));
}

export function formatFreshness(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "No projection";
  const s = Math.max(0, Math.trunc(seconds));
  if (s < 60) return `${s}s old`;
  const minutes = Math.floor(s / 60);
  if (minutes < 60) return `${minutes}m old`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h old`;
  return `${Math.floor(hours / 24)}d old`;
}

export function topologySeverityVariant(severity: TopologySeverity | "" | null | undefined): BadgeVariant {
  const value = String(severity ?? "").toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "medium") return "medium";
  if (value === "low") return "low";
  if (value === "informational" || value === "info") return "info";
  return "neutral";
}

export function ipScopeLabel(scope: string | null | undefined): string {
  return labelForIpScope(scope);
}

export function ipScopeVariant(scope: string | null | undefined): BadgeVariant {
  const label = labelForIpScope(scope);
  if (label === "Public") return "info";
  if (label === "Internal" || label === "Private") return "low";
  if (label === "CGNAT" || label === "Reserved/Test") return "medium";
  if (label === "Invalid") return "critical";
  return "neutral";
}
