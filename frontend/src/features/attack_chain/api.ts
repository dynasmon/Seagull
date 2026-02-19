import { apiGet, apiPost } from "@/shared/lib/http";
import type { AttackChainCaseWithSteps, AttackChainCasesPage } from "./types";

export type ListAttackChainCasesParams = {
  page_size?: number;
  cursor?: string | null;
  agent_id?: string;
  suspect_ip?: string;
  status?: "open" | "closed" | "all";
  min_score?: number;
  since?: string;
};

export function listAttackChainCases(params?: ListAttackChainCasesParams) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));

  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.suspect_ip) q.set("suspect_ip", params.suspect_ip);
  if (params?.status && params.status !== "all") q.set("status", params.status);
  if (typeof params?.min_score === "number" && Number.isFinite(params.min_score)) q.set("min_score", String(params.min_score));
  if (params?.since) q.set("since", params.since);

  return apiGet<AttackChainCasesPage>(`/api/attack-chain/cases?${q.toString()}`);
}

export function getAttackChainCaseFull(caseId: number) {
  return apiGet<AttackChainCaseWithSteps>(`/api/attack-chain/cases/${caseId}/full`);
}

export function closeAttackChainCase(caseId: number) {
  return apiPost<{ status: string; case_id: number; already_closed?: boolean }>(`/api/attack-chain/cases/${caseId}/close`);
}
