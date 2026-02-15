import { apiGet } from "@/shared/lib/http";

import type { NetEvent } from "../../types";
import type { ProtocolIntelIndicatorKind, ProtocolIntelSummaryResponse } from "./types";

export function getProtocolIntelSummary(params?: { since_minutes?: number; limit?: number; agent_id?: string }) {
  const q = new URLSearchParams();
  q.set("since_minutes", String(params?.since_minutes ?? 60 * 12));
  q.set("limit", String(params?.limit ?? 25));

  const agent = (params?.agent_id ?? "").trim();
  if (agent) q.set("agent_id", agent);

  return apiGet<ProtocolIntelSummaryResponse>(`/api/events/network/summary?${q.toString()}`);
}

export function getProtocolIntelSamples(params: {
  kind: ProtocolIntelIndicatorKind;
  value: string;
  since_minutes?: number;
  limit?: number;
  agent_id?: string;
}) {
  const q = new URLSearchParams();
  q.set("kind", params.kind);
  q.set("value", params.value);
  q.set("since_minutes", String(params.since_minutes ?? 60 * 12));
  q.set("limit", String(params.limit ?? 50));

  const agent = (params.agent_id ?? "").trim();
  if (agent) q.set("agent_id", agent);

  return apiGet<NetEvent[]>(`/api/events/network/samples?${q.toString()}`);
}
