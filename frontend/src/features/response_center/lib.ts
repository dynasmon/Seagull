import type { StatusVariant } from "@/shared/components/StatusPill";
import type { SeverityLevel } from "@/shared/lib/severity";

export function statusVariant(status: string): StatusVariant {
  switch (String(status || "").toLowerCase()) {
    case "pending":
      return "neutral";
    case "delivered":
      return "info";
    case "running":
      return "pending";
    case "success":
      return "success";
    case "failed":
      return "danger";
    case "cancelled":
    case "expired":
      return "inactive";
    default:
      return "neutral";
  }
}

export function riskVariant(risk: string): SeverityLevel {
  switch (String(risk || "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "neutral";
  }
}

export function categoryLabel(category: string): string {
  switch (String(category || "").toLowerCase()) {
    case "forensics":
      return "Forensics";
    case "diagnostics":
      return "Diagnostics";
    case "containment":
      return "Containment";
    default:
      return category || "Other";
  }
}

export function isTerminalStatus(status: string): boolean {
  return ["success", "failed", "cancelled", "expired"].includes(String(status || "").toLowerCase());
}

export function isCancellableStatus(status: string): boolean {
  return ["pending", "delivered"].includes(String(status || "").toLowerCase());
}

export function sinceTokenToIso(token: string): string {
  const ms: Record<string, number> = {
    "1h": 3_600_000,
    "24h": 86_400_000,
    "7d": 604_800_000,
  };
  const window = ms[token];
  if (!window) return "";
  return new Date(Date.now() - window).toISOString();
}
