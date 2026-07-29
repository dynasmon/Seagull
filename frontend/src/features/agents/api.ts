import { apiGet, apiPatch, apiPost, apiPut } from "@/shared/lib/http";
import type { ApiGetOptions } from "@/shared/lib/http";
import type {
  AgentDetail,
  AgentEnrollmentTicket,
  AgentEnrollmentTicketIn,
  AgentOnboardingInfo,
  AgentPublic,
  AgentUpdateIn,
  ResponseActionCreateIn,
  ResponseActionOut,
  ResponseActionResultOut
} from "./types";

export function listAgents(opts?: ApiGetOptions) {
  return apiGet<AgentPublic[]>("/api/agents", opts);
}

export function getAgent(agentId: string, opts?: ApiGetOptions) {
  return apiGet<AgentDetail>(`/api/agents/${encodeURIComponent(agentId)}`, opts);
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

export function getAgentOnboarding(opts?: ApiGetOptions) {
  return apiGet<AgentOnboardingInfo>("/api/agents/onboarding", opts);
}

export function createEnrollmentTicket(payload: AgentEnrollmentTicketIn) {
  return apiPost<AgentEnrollmentTicket>("/api/agents/enrollment-tickets", payload);
}

export function createResponseAction(payload: ResponseActionCreateIn) {
  return apiPost<ResponseActionOut>("/api/response/actions", payload);
}

export function listResponseActions(params?: { agent_id?: string; status?: string; limit?: number }) {
  const q = new URLSearchParams();
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.status) q.set("status", params.status);
  if (typeof params?.limit === "number") q.set("limit", String(params.limit));
  const suffix = q.toString() ? `?${q.toString()}` : "";
  return apiGet<ResponseActionOut[]>(`/api/response/actions${suffix}`);
}

export function getResponseAction(actionId: number) {
  return apiGet<ResponseActionOut>(`/api/response/actions/${actionId}`);
}

export function getResponseActionResult(actionId: number) {
  return apiGet<ResponseActionResultOut>(`/api/response/actions/${actionId}/result`);
}

export function cancelResponseAction(actionId: number) {
  return apiPost<ResponseActionOut>(`/api/response/actions/${actionId}/cancel`);
}
