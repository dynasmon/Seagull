import { apiGet, apiPatch } from "@/shared/lib/http";
import type { CursorPage } from "@/shared/types/pagination";

import type {
  UebaBaseline,
  UebaBaselineStatus,
  UebaDetectorRun,
  UebaDetectorState,
  UebaFinding,
  UebaFindingDetail,
  UebaFindingStatus,
  UebaRunStatus,
  UebaSeverity,
  UebaSummary,
} from "./types";

export function getUebaSummary(opts?: { signal?: AbortSignal }) {
  return apiGet<UebaSummary>("/api/ueba/summary", { cacheMs: 0, signal: opts?.signal });
}

export function listUebaFindings(params?: {
  page_size?: number;
  cursor?: string | null;
  detector_id?: string | null;
  agent_id?: string | null;
  entity_type?: string | null;
  entity_value?: string | null;
  metric_name?: string | null;
  status?: UebaFindingStatus | "all" | null;
  severity?: UebaSeverity | "all" | null;
  min_risk_score?: number | null;
  signal?: AbortSignal;
}) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.detector_id) q.set("detector_id", params.detector_id);
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.entity_type) q.set("entity_type", params.entity_type);
  if (params?.entity_value) q.set("entity_value", params.entity_value);
  if (params?.metric_name) q.set("metric_name", params.metric_name);
  if (params?.status && params.status !== "all") q.set("status", params.status);
  if (params?.severity && params.severity !== "all") q.set("severity", params.severity);
  if (params?.min_risk_score != null) q.set("min_risk_score", String(params.min_risk_score));
  return apiGet<CursorPage<UebaFinding>>(`/api/ueba/findings?${q.toString()}`, {
    cacheMs: 0,
    signal: params?.signal,
  });
}

export function getUebaFinding(findingId: number, opts?: { signal?: AbortSignal }) {
  return apiGet<UebaFindingDetail>(`/api/ueba/findings/${findingId}`, {
    cacheMs: 0,
    signal: opts?.signal,
  });
}

export function listUebaBaselines(params?: {
  page_size?: number;
  cursor?: string | null;
  detector_id?: string | null;
  agent_id?: string | null;
  entity_type?: string | null;
  entity_value?: string | null;
  metric_name?: string | null;
  status?: UebaBaselineStatus | "all" | null;
  signal?: AbortSignal;
}) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.detector_id) q.set("detector_id", params.detector_id);
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.entity_type) q.set("entity_type", params.entity_type);
  if (params?.entity_value) q.set("entity_value", params.entity_value);
  if (params?.metric_name) q.set("metric_name", params.metric_name);
  if (params?.status && params.status !== "all") q.set("status", params.status);
  return apiGet<CursorPage<UebaBaseline>>(`/api/ueba/baselines?${q.toString()}`, {
    cacheMs: 0,
    signal: params?.signal,
  });
}

export function listUebaDetectors(opts?: { signal?: AbortSignal }) {
  return apiGet<UebaDetectorState[]>("/api/ueba/detectors", { cacheMs: 0, signal: opts?.signal });
}

export function listUebaRuns(params?: {
  page_size?: number;
  cursor?: string | null;
  detector_id?: string | null;
  status?: UebaRunStatus | "all" | null;
  signal?: AbortSignal;
}) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.detector_id) q.set("detector_id", params.detector_id);
  if (params?.status && params.status !== "all") q.set("status", params.status);
  return apiGet<CursorPage<UebaDetectorRun>>(`/api/ueba/runs?${q.toString()}`, {
    cacheMs: 0,
    signal: params?.signal,
  });
}

export function triageUebaFinding(
  findingId: number,
  body: { status: UebaFindingStatus; cooldown_extension_minutes?: number },
) {
  return apiPatch<UebaFindingDetail>(`/api/ueba/findings/${findingId}`, body);
}
