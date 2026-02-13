import { apiDelete, apiGet, apiPost, apiPut } from "@/shared/lib/http";

import type { CorrelationRule, CorrelationRuleIn, CorrelationRunOut } from "./types";

export function getCorrelationRules() {
  return apiGet<CorrelationRule[]>("/api/correlations/rules");
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

export function runCorrelations(params?: { limit?: number; max_age_minutes?: number; sample_limit?: number }) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 500));
  q.set("max_age_minutes", String(params?.max_age_minutes ?? 1440));
  q.set("sample_limit", String(params?.sample_limit ?? 25));
  return apiPost<CorrelationRunOut>(`/api/correlations/run?${q.toString()}`);
}
