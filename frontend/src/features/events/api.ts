import { apiGet } from "@/shared/lib/http";
import type { Agent, NetEvent } from "./types";

export function getAgents() {
  return apiGet<Agent[]>("/api/agents");
}

export function getRecentEvents(params?: {
  limit?: number;
  agent_id?: string;
  event_type?: string;
  window_minutes?: number;
  search?: string;
}) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 500));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.event_type) q.set("event_type", params.event_type);
  if (typeof params?.window_minutes === "number") q.set("window_minutes", String(params.window_minutes));
  if (params?.search) q.set("search", params.search);

  return apiGet<NetEvent[]>(`/api/events/recent?${q.toString()}`);
}
