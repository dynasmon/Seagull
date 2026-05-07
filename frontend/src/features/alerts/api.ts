import { apiDelete, apiGet, apiPatch, apiPost } from "@/shared/lib/http";
import type { CursorPage } from "@/shared/types/pagination";

import type { Alert, AlertEvidenceItem, AlertTriageIn, RuleGovernanceHistory, RuleOverrideIn, RuleOut } from "./types";

export function getRecentAlerts(params?: { limit?: number }) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 200));
  return apiGet<Alert[]>(`/api/alerts/recent?${q.toString()}`);
}

/**
 * Cursor/keyset pagination endpoint (recommended).
 * Returns newest alerts first. Use `next_cursor` to fetch older pages.
 */
export function getAlertsPage(params?: {
  page_size?: number;
  cursor?: string | null;
  severity?: string;
  rule_id?: string;
}) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 200));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.rule_id) q.set("rule_id", params.rule_id);
  return apiGet<CursorPage<Alert>>(`/api/alerts?${q.toString()}`);
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

export function getAlertRuleHistory(ruleId: string, params?: { limit?: number }) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 100));
  return apiGet<RuleGovernanceHistory[]>(
    `/api/alerts/rules/${encodeURIComponent(ruleId)}/history?${q.toString()}`
  );
}

export function getAlert(alertId: number) {
  return apiGet<Alert>(`/api/alerts/${alertId}`);
}

export function triageAlert(alertId: number, body: AlertTriageIn) {
  return apiPatch<Alert>(`/api/alerts/${alertId}/triage`, body);
}

export function getAlertEvidence(alertId: number) {
  return apiGet<AlertEvidenceItem[]>(`/api/alerts/${alertId}/evidence`);
}
