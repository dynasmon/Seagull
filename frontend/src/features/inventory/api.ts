import { apiGet } from "@/shared/lib/http";

import type { InventoryOverviewSnapshot, InventorySnapshotOut } from "./types";

export function getInventoryOverview(params?: { window_minutes?: number; agent_id?: string }) {
  const q = new URLSearchParams();
  if (params?.window_minutes) q.set("window_minutes", String(params.window_minutes));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  const qs = q.toString();
  return apiGet<InventoryOverviewSnapshot>(`/api/inventory/overview${qs ? `?${qs}` : ""}`);
}

export function getInventoryLatest(agentId: string) {
  return apiGet<InventorySnapshotOut>(`/api/inventory/${encodeURIComponent(agentId)}/latest`);
}

export function getInventoryHistory(agentId: string, params?: { limit?: number }) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 20));
  return apiGet<InventorySnapshotOut[]>(`/api/inventory/${encodeURIComponent(agentId)}/history?${q.toString()}`);
}
