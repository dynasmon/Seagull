import type { HygieneDomain } from "../types";

export function buildInventoryUrl(
  current: URLSearchParams,
  updates: {
    agentId?: string;
    windowMinutes?: number;
    domain?: HygieneDomain;
    clearDrawerParams?: boolean;
  }
): URLSearchParams {
  const next = new URLSearchParams(current);

  if (updates.agentId !== undefined || updates.clearDrawerParams) {
    next.delete("snapshot_id");
    next.delete("open_drawer");
  }

  if (updates.agentId !== undefined) {
    if (updates.agentId && updates.agentId !== "__all") {
      next.set("agent_id", updates.agentId);
    } else {
      next.delete("agent_id");
    }
  }

  if (updates.windowMinutes !== undefined && Number.isFinite(updates.windowMinutes)) {
    next.set("window_minutes", String(updates.windowMinutes));
  }

  if (updates.domain !== undefined) {
    if (updates.domain === "dashboard") {
      next.delete("view");
    } else {
      next.set("view", updates.domain);
    }
  }

  return next;
}
