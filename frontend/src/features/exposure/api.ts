import { apiGet, apiPost } from "@/shared/lib/http";
import { CursorPage } from "@/shared/types/pagination";
import {
  ExposureAssetDetail,
  ExposureAssetPosture,
  ExposureAssetsParams,
  ExposureAttackPath,
  ExposureFinding,
  ExposureFindingsParams,
  ExposureGraph,
  ExposureGraphParams,
  ExposureInvestigationResult,
  ExposurePathsParams,
  ExposureRecalculateResult,
  ExposureSummary,
  ExposureTriageResponseAction,
} from "./types";

export function getExposureSummary(signal?: AbortSignal) {
  return apiGet<ExposureSummary>("/api/exposure/summary", { signal });
}

export function listExposureAssets(params?: ExposureAssetsParams) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.q) q.set("q", params.q);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.min_score != null) q.set("min_score", String(params.min_score));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.status) q.set("status", params.status);
  if (params?.reason_code) q.set("reason_code", params.reason_code);
  if (params?.has_attack_chain != null) q.set("has_attack_chain", String(params.has_attack_chain));
  if (params?.has_critical_vuln != null) q.set("has_critical_vuln", String(params.has_critical_vuln));
  if (params?.has_persistence_signal != null) q.set("has_persistence_signal", String(params.has_persistence_signal));
  if (params?.sort) q.set("sort", params.sort);
  return apiGet<CursorPage<ExposureAssetPosture>>(`/api/exposure/assets?${q.toString()}`, {
    cacheMs: 0,
    signal: params?.signal,
  });
}

export function getExposureAssetDetail(assetKey: string, signal?: AbortSignal) {
  return apiGet<ExposureAssetDetail>(`/api/exposure/assets/${encodeURIComponent(assetKey)}`, {
    cacheMs: 0,
    signal,
  });
}

export function getExposureAssetGraph(assetKey: string, params?: ExposureGraphParams) {
  const q = new URLSearchParams();
  if (params?.depth != null) q.set("depth", String(params.depth));
  if (params?.min_confidence != null) q.set("min_confidence", String(params.min_confidence));
  if (params?.max_nodes != null) q.set("max_nodes", String(params.max_nodes));
  if (params?.max_edges != null) q.set("max_edges", String(params.max_edges));
  if (params?.include_resolved != null) q.set("include_resolved", String(params.include_resolved));
  if (params?.node_types?.length) {
    for (const t of params.node_types) q.append("node_types", t);
  }
  if (params?.edge_types?.length) {
    for (const t of params.edge_types) q.append("edge_types", t);
  }
  const qs = q.toString();
  return apiGet<ExposureGraph>(
    `/api/exposure/assets/${encodeURIComponent(assetKey)}/graph${qs ? `?${qs}` : ""}`,
    { cacheMs: 0, signal: params?.signal },
  );
}

export function listExposurePaths(params?: ExposurePathsParams) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 25));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.min_score != null) q.set("min_score", String(params.min_score));
  if (params?.reason_code) q.set("reason_code", params.reason_code);
  return apiGet<CursorPage<ExposureAttackPath>>(`/api/exposure/paths?${q.toString()}`, {
    signal: params?.signal,
  });
}

export function listExposureFindings(params?: ExposureFindingsParams) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.asset_key) q.set("asset_key", params.asset_key);
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.finding_type) q.set("finding_type", params.finding_type);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.status) q.set("status", params.status);
  if (params?.q) q.set("q", params.q);
  return apiGet<CursorPage<ExposureFinding>>(`/api/exposure/findings?${q.toString()}`, {
    cacheMs: 0,
    signal: params?.signal,
  });
}

export function requestExposureRecalculate() {
  return apiPost<ExposureRecalculateResult>("/api/exposure/recalculate");
}

export function openAssetInvestigation(assetKey: string) {
  return apiPost<ExposureInvestigationResult>(
    `/api/exposure/assets/${encodeURIComponent(assetKey)}/investigation`,
  );
}

export function createAssetTriageAction(assetKey: string) {
  return apiPost<ExposureTriageResponseAction>(
    `/api/exposure/assets/${encodeURIComponent(assetKey)}/response-actions/triage`,
  );
}
