import { apiGet } from "@/shared/lib/http";
import type { ApiGetOptions } from "@/shared/lib/http";
import type { Agent, EventHuntResponse, NetEvent } from "./types";

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
}, opts?: ApiGetOptions) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 500));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.event_type) q.set("event_type", params.event_type);
  const sinceMinutes = typeof params?.since_minutes === "number" ? params.since_minutes : params?.window_minutes;
  if (typeof sinceMinutes === "number") q.set("since_minutes", String(sinceMinutes));
  if (params?.search) q.set("search", params.search);

  return apiGet<NetEvent[]>(`/api/events/recent?${q.toString()}`, opts);
}

export function huntEvents(params?: {
  page_size?: number;
  cursor?: string | null;
  agent_id?: string;
  event_type?: string;
  since_minutes?: number;
  start_ts?: string;
  end_ts?: string;
  search?: string;
}, opts?: ApiGetOptions) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 100));
  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.event_type) q.set("event_type", params.event_type);
  if (typeof params?.since_minutes === "number") q.set("since_minutes", String(params.since_minutes));
  if (params?.start_ts) q.set("start_ts", params.start_ts);
  if (params?.end_ts) q.set("end_ts", params.end_ts);
  if (params?.search) q.set("search", params.search);

  return apiGet<EventHuntResponse>(`/api/events?${q.toString()}`, opts);
}
