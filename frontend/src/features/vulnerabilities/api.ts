import { apiGet, apiPatch } from "@/shared/lib/http";
import type { CursorPage } from "@/shared/types/pagination";

import type { VulnFinding, VulnFindingPatchIn, VulnScan, VulnSummary } from "./types";

export function getVulnSummary(params?: { active_within_days?: number; include_suppressed?: boolean }) {
  const q = new URLSearchParams();
  q.set("active_within_days", String(params?.active_within_days ?? 30));
  if (params?.include_suppressed) q.set("include_suppressed", "true");
  return apiGet<VulnSummary>(`/api/vuln/summary?${q.toString()}`);
}

export function getVulnFindingsPage(params?: {
  page_size?: number;
  cursor?: string | null;
  asset_agent_id?: string;
  reporter_agent_id?: string;
  status?: string;
  min_severity?: string;
  cve?: string;
  q?: string;
  include_suppressed?: boolean;
}) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.asset_agent_id) q.set("asset_agent_id", params.asset_agent_id);
  if (params?.reporter_agent_id) q.set("reporter_agent_id", params.reporter_agent_id);
  if (params?.status) q.set("status_q", params.status);
  if (params?.min_severity) q.set("min_severity", params.min_severity);
  if (params?.cve) q.set("cve", params.cve);
  if (params?.q) q.set("q", params.q);
  if (params?.include_suppressed) q.set("include_suppressed", "true");
  return apiGet<CursorPage<VulnFinding>>(`/api/vuln/findings?${q.toString()}`);
}

export function getVulnFinding(id: number) {
  return apiGet<VulnFinding>(`/api/vuln/findings/${encodeURIComponent(String(id))}`);
}

export function patchVulnFinding(id: number, patch: VulnFindingPatchIn) {
  return apiPatch<VulnFinding>(`/api/vuln/findings/${encodeURIComponent(String(id))}`, patch);
}

export function getVulnScansPage(params?: {
  page_size?: number;
  cursor?: string | null;
  reporter_agent_id?: string;
  status?: string;
  tool?: string;
}) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.reporter_agent_id) q.set("reporter_agent_id", params.reporter_agent_id);
  if (params?.status) q.set("status_q", params.status);
  if (params?.tool) q.set("tool", params.tool);
  return apiGet<CursorPage<VulnScan>>(`/api/vuln/scans?${q.toString()}`);
}
