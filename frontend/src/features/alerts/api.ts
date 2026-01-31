import { apiDelete, apiGet, apiPatch, apiPost } from "@/shared/lib/http";

import type { Alert, RuleOverrideIn, RuleOut } from "./types";

export function getRecentAlerts(params?: { limit?: number }) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 200));
  return apiGet<Alert[]>(`/api/alerts/recent?${q.toString()}`);
}

export function runAllRules() {
  return apiPost<Alert[]>("/api/alerts/run/all");
}

export function getAlertRules() {
  return apiGet<RuleOut[]>("/api/alerts/rules");
}

export function patchAlertRule(ruleId: string, body: RuleOverrideIn) {
  return apiPatch<RuleOut>(`/api/alerts/rules/${encodeURIComponent(ruleId)}`, body);
}

export function resetAlertRule(ruleId: string) {
  return apiDelete<void>(`/api/alerts/rules/${encodeURIComponent(ruleId)}`);
}
