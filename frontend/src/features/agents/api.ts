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

export function setAgentConfig(agentId: string, config: Record<string, any>) {
  // Backend expects: { config: {...} }? No — in our backend it expects AgentConfigUpdateIn = { config: {...} }
  // So we send { config } to match exactly.
  return apiPut<AgentDetail>(`/api/agents/${encodeURIComponent(agentId)}/config`, { config });
}

export function enableAgent(agentId: string) {
  return apiPost<AgentDetail>(`/api/agents/${encodeURIComponent(agentId)}/enable`);
}

export function disableAgent(agentId: string) {
  return apiPost<AgentDetail>(`/api/agents/${encodeURIComponent(agentId)}/disable`);
}
