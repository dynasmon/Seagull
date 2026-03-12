import { apiGet } from "@/shared/lib/http";

import type { AuditQueryOut, LoginEvidenceEvent, RuntimeConfigOut } from "./types";

export type GetAuditEventsParams = {
  limit?: number;
  event_type?: string;
  action?: string;
  outcome?: string;
  resource_type?: string;
  actor_username?: string;
  since?: string;
  until?: string;
};

export function getAuditEvents(params?: GetAuditEventsParams) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 100));

  if (params?.event_type) q.set("event_type", params.event_type);
  if (params?.action) q.set("action", params.action);
  if (params?.outcome) q.set("outcome", params.outcome);
  if (params?.resource_type) q.set("resource_type", params.resource_type);
  if (params?.actor_username) q.set("actor_username", params.actor_username);
  if (params?.since) q.set("since", params.since);
  if (params?.until) q.set("until", params.until);

  return apiGet<AuditQueryOut>(`/api/admin/audit/events?${q.toString()}`);
}

export function getAdminLoginEvidence(limit = 100, includeFailed = true) {
  const q = new URLSearchParams();
  q.set("limit", String(limit));
  if (includeFailed) q.set("include_failed", "true");
  return apiGet<LoginEvidenceEvent[]>(`/api/admin/login-history?${q.toString()}`);
}

export function getRuntimeConfig() {
  return apiGet<RuntimeConfigOut>("/api/admin/runtime-config");
}
