import { apiGet, apiPatch, apiPost, apiPut } from "@/shared/lib/http";
import type { AgentDetail, AgentPublic, AgentUpdateIn } from "./types";

export function listAgents() {
  return apiGet<AgentPublic[]>("/api/agents");
}

export function getAgent(agentId: string) {
  return apiGet<AgentDetail>(`/api/agents/${encodeURIComponent(agentId)}`);
}

export function updateAgent(agentId: string, patch: AgentUpdateIn) {
  return apiPatch<AgentDetail>(`/api/agents/${encodeURIComponent(agentId)}`, patch);
}

/**
 * Backend endpoints return 204 No Content for state/config operations.
 * To keep the UI simple, we re-fetch the agent details after each operation.
 */
export async function setAgentConfig(agentId: string, config: Record<string, any>) {
  await apiPut<void>(`/api/agents/${encodeURIComponent(agentId)}/config`, { config });
  return getAgent(agentId);
}

export async function enableAgent(agentId: string) {
  await apiPost<void>(`/api/agents/${encodeURIComponent(agentId)}/enable`);
  return getAgent(agentId);
}

export async function disableAgent(agentId: string) {
  await apiPost<void>(`/api/agents/${encodeURIComponent(agentId)}/disable`);
  return getAgent(agentId);
}
