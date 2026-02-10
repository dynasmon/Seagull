import { apiGet } from "@/shared/lib/http";

import type { SshSummaryResponse } from "./types";

export function getSshSummary(params?: {
  since_minutes?: number;
  limit?: number;
  agent_id?: string;
}) {
  const q = new URLSearchParams();
  q.set("since_minutes", String(params?.since_minutes ?? 60 * 24));
  q.set("limit", String(params?.limit ?? 20));
  const agent = (params?.agent_id ?? "").trim();
  if (agent) q.set("agent_id", agent);

  return apiGet<SshSummaryResponse>(`/api/events/ssh/summary?${q.toString()}`);
}
