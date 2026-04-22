import type { VulnScan } from "./types";

export const PHASE_SEQ: string[] = [
  "queued",
  "acknowledged",
  "running",
  "collecting_inventory",
  "analyzing_exposure",
  "querying_source",
  "normalizing_findings",
  "ingesting_results",
  "completed",
  "failed",
  "cancelled",
];

export const STAT_DISPLAY: Array<{ keys: string[]; label: string }> = [
  { keys: ["inventory_packages", "packages_collected"], label: "packages collected" },
  { keys: ["queried_packages", "packages_queried", "packages_analyzed"], label: "packages queried" },
  { keys: ["received_vulns", "vulnerabilities_matched", "vulns_matched"], label: "vulnerabilities matched" },
  { keys: ["emitted_findings", "findings_emitted"], label: "findings emitted" },
  { keys: ["stored_findings", "findings_stored"], label: "findings stored" },
  { keys: ["exposed_ports"], label: "exposed ports" },
  { keys: ["exposure_surface_score"], label: "exposure score" },
  { keys: ["errors_count", "error_count"], label: "errors" },
];

export function fmtSec(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "-";
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  const r = Math.round(sec % 60);
  if (m < 60) return r ? `${m}m ${r}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mr = m % 60;
  return mr ? `${h}h ${mr}m` : `${h}h`;
}

export const fmtSeconds = fmtSec;

export function fmtWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

export function fmtAge(iso?: string | null): string {
  if (!iso) return "-";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  const delta = Date.now() - t;
  if (delta < 10_000) return "just now";
  const sec = Math.floor(delta / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

export function fmtAbsoluteAndAge(iso?: string | null): string {
  if (!iso) return "-";
  return `${fmtWhen(iso)} · ${fmtAge(iso)}`;
}

export function scanVariant(state: string): "info" | "neutral" | "critical" {
  const s = String(state || "").toLowerCase();
  if (s === "completed") return "neutral";
  if (s === "failed" || s === "cancelled") return "critical";
  return "info";
}

export function isLiveScan(state: string): boolean {
  const s = String(state || "").toLowerCase();
  return s === "queued" || s === "acknowledged" || s === "running";
}

export function applyLifecycleScanPatch(existing: VulnScan, patch: Record<string, any>): VulnScan {
  return {
    ...existing,
    id: patch.id ?? existing.id,
    status: patch.status ?? existing.status,
    lifecycle_state: patch.lifecycle_state ?? existing.lifecycle_state,
    current_phase: patch.current_phase ?? existing.current_phase,
    acknowledged_at: "acknowledged_at" in patch ? patch.acknowledged_at : existing.acknowledged_at,
    started_at: "started_at" in patch ? patch.started_at : existing.started_at,
    finished_at: "finished_at" in patch ? patch.finished_at : existing.finished_at,
    last_progress_at: patch.last_progress_at ?? existing.last_progress_at,
    duration_ms: "duration_ms" in patch ? patch.duration_ms : existing.duration_ms,
    error_summary: "error_summary" in patch ? patch.error_summary : existing.error_summary,
    stats: patch.stats ? (patch.stats as Record<string, any>) : existing.stats,
    phase_timestamps: patch.phase_timestamps
      ? (patch.phase_timestamps as Record<string, string>)
      : existing.phase_timestamps,
    updated_at: patch.updated_at ?? existing.updated_at,
  };
}

export function buildVulnScanFromPatch(patch: Record<string, any>): VulnScan | null {
  const uuid = String(patch.scan_uuid || "").trim();
  if (!uuid) return null;
  const now = new Date().toISOString();
  return {
    id: patch.id ?? 0,
    scan_uuid: uuid,
    reporter_agent_id: patch.reporter_agent_id ?? null,
    target: patch.target ?? null,
    tool: patch.tool ?? "unknown",
    tool_version: patch.tool_version ?? null,
    status: patch.status ?? "queued",
    lifecycle_state: patch.lifecycle_state ?? "queued",
    current_phase: patch.current_phase ?? "queued",
    queued_at: patch.queued_at ?? now,
    acknowledged_at: patch.acknowledged_at ?? null,
    started_at: patch.started_at ?? null,
    finished_at: patch.finished_at ?? null,
    last_progress_at: patch.last_progress_at ?? now,
    duration_ms: patch.duration_ms ?? null,
    trigger_source: patch.trigger_source ?? "unknown",
    error_summary: patch.error_summary ?? null,
    stats: (patch.stats ?? {}) as Record<string, any>,
    phase_timestamps: (patch.phase_timestamps ?? {}) as Record<string, string>,
    scope: (patch.scope ?? {}) as Record<string, any>,
    config: (patch.config ?? {}) as Record<string, any>,
    updated_at: patch.updated_at ?? now,
    created_at: patch.created_at ?? now,
  };
}
