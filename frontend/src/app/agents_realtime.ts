import type { AgentPublic } from "@/features/agents/types";
import type { PortalRealtimeEventPayloadMap } from "@/shared/realtime/types";

export type AgentHeartbeatPayload = PortalRealtimeEventPayloadMap["ui.agents.presence.patch"];

export type ApplyAgentHeartbeatResult = {
  agents: AgentPublic[];
  updated: boolean;
  agentId: string;
};

function normalizeIso(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!text) return null;
  const ts = Date.parse(text);
  if (!Number.isFinite(ts)) return null;
  return new Date(ts).toISOString();
}

export function applyAgentHeartbeatRealtime(
  agents: AgentPublic[],
  payload: AgentHeartbeatPayload | null | undefined,
  eventTimestamp: string,
): ApplyAgentHeartbeatResult {
  const agentId = String(payload?.agent_id || "").trim();
  if (!agentId) {
    return { agents, updated: false, agentId: "" };
  }

  const nextLastSeen = normalizeIso(payload?.last_seen_at) ?? normalizeIso(eventTimestamp);
  const nextStatus = typeof payload?.status === "string" ? payload.status.trim().slice(0, 32) : "";
  const nextRevoked = typeof payload?.is_revoked === "boolean" ? payload.is_revoked : null;

  let updated = false;
  const nextAgents = agents.map((row) => {
    if (row.agent_id !== agentId) return row;
    updated = true;

    const nextMetrics = {
      ...(row.metrics || {}),
      ...(nextStatus ? { status: nextStatus } : {}),
    };

    return {
      ...row,
      last_seen_at: nextLastSeen ?? row.last_seen_at,
      is_revoked: nextRevoked === null ? row.is_revoked : nextRevoked,
      metrics: nextMetrics,
    };
  });

  return {
    agents: nextAgents,
    updated,
    agentId,
  };
}
