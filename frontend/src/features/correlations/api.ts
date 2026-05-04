import { apiDelete, apiGet, apiPost, apiPut } from "@/shared/lib/http";

import type {
  CorrelationDurableIncident,
  CorrelationIncidentDetail,
  CorrelationIncidentStatusUpdate,
  CorrelationLifecycleStatus,
  CorrelationRule,
  CorrelationRuleIn,
  CorrelationRuleRunResult,
} from "./types";

export function getCorrelationIncidents(params?: {
  status?: CorrelationLifecycleStatus | "all" | null;
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
}) {
  const q = new URLSearchParams();
  if (params?.status && params.status !== "all") q.set("status", String(params.status));
  q.set("limit", String(params?.limit ?? 25));
  q.set("offset", String(params?.offset ?? 0));
  return apiGet<CorrelationDurableIncident[]>(`/api/correlations/incidents?${q.toString()}`, {
    cacheMs: 0,
    signal: params?.signal,
  });
}

export function getCorrelationIncident(incidentId: number, opts?: { signal?: AbortSignal }) {
  return apiGet<CorrelationIncidentDetail>(`/api/correlations/incidents/${incidentId}`, {
    cacheMs: 0,
    signal: opts?.signal,
  });
}

export function updateCorrelationIncidentStatus(incidentId: number, payload: CorrelationIncidentStatusUpdate) {
  return apiPost<CorrelationIncidentDetail>(`/api/correlations/incidents/${incidentId}/status`, payload);
}

export function getCorrelationRules(opts?: { signal?: AbortSignal }) {
  return apiGet<CorrelationRule[]>("/api/correlations/rules", {
    cacheMs: 0,
    signal: opts?.signal,
  });
}

export function createCorrelationRule(payload: CorrelationRuleIn) {
  return apiPost<CorrelationRule>("/api/correlations/rules", payload);
}

export function updateCorrelationRule(ruleId: number, payload: CorrelationRuleIn) {
  return apiPut<CorrelationRule>(`/api/correlations/rules/${ruleId}`, payload);
}

export function deleteCorrelationRule(ruleId: number) {
  return apiDelete<{ ok: boolean }>(`/api/correlations/rules/${ruleId}`);
}

export function runCorrelations(params?: {
  limit?: number;
  max_age_minutes?: number;
  sample_limit?: number;
}) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 500));
  q.set("max_age_minutes", String(params?.max_age_minutes ?? 1440));
  q.set("sample_limit", String(params?.sample_limit ?? 25));
  return apiPost<CorrelationRuleRunResult>(`/api/correlations/run?${q.toString()}`);
}
