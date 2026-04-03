import { apiGet } from "@/shared/lib/http";
import type { Agent, NetEvent } from "./types";

export function getAgents() {
  return apiGet<Agent[]>("/api/agents");
}

export function getRecentEvents(params?: {
  limit?: number;
  agent_id?: string;
  event_type?: string;
  since_minutes?: number;
  window_minutes?: number;
  search?: string;
}) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 500));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.event_type) q.set("event_type", params.event_type);
  const sinceMinutes = typeof params?.since_minutes === "number" ? params.since_minutes : params?.window_minutes;
  if (typeof sinceMinutes === "number") q.set("since_minutes", String(sinceMinutes));
  if (params?.search) q.set("search", params.search);

  return apiGet<NetEvent[]>(`/api/events/recent?${q.toString()}`);
}
