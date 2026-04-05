import { apiDelete, apiGet, apiPost, apiPut } from "@/shared/lib/http";
import type {
  InvestigationBookmarkCreateIn,
  InvestigationBookmarkCreateResult,
  InvestigationBookmarksPage,
  InvestigationNote,
  InvestigationPinOptions,
  InvestigationWorkspace,
  InvestigationWorkspaceCreateIn,
  InvestigationWorkspacePage,
  InvestigationWorkspaceUpdateIn,
} from "./types";

export type ListInvestigationWorkspacesParams = {
  page_size?: number;
  cursor?: string | null;
  status?: string;
  severity?: string;
  priority?: string;
  assignee?: string;
  linked_attack_chain_case_id?: number;
  agent_id?: string;
  search?: string;
};

export function listInvestigationWorkspaces(params?: ListInvestigationWorkspacesParams) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 50));

  if (params?.cursor) q.set("cursor", params.cursor);
  if (params?.status) q.set("status", params.status);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.priority) q.set("priority", params.priority);
  if (params?.assignee) q.set("assignee", params.assignee);
  if (typeof params?.linked_attack_chain_case_id === "number") q.set("linked_attack_chain_case_id", String(params.linked_attack_chain_case_id));
  if (params?.agent_id) q.set("agent_id", params.agent_id);
  if (params?.search) q.set("search", params.search);

  return apiGet<InvestigationWorkspacePage>(`/api/investigations/workspaces?${q.toString()}`);
}

export function createInvestigationWorkspace(payload: InvestigationWorkspaceCreateIn) {
  return apiPost<InvestigationWorkspace>("/api/investigations/workspaces", payload);
}

export function getInvestigationWorkspace(workspaceId: number) {
  return apiGet<InvestigationWorkspace>(`/api/investigations/workspaces/${workspaceId}`);
}

export function updateInvestigationWorkspace(workspaceId: number, payload: InvestigationWorkspaceUpdateIn) {
  return apiPut<InvestigationWorkspace>(`/api/investigations/workspaces/${workspaceId}`, payload);
}

export function linkAttackChainCaseToWorkspace(workspaceId: number, caseId: number, primaryAgentId?: string | null) {
  return updateInvestigationWorkspace(workspaceId, {
    linked_attack_chain_case_id: caseId,
    primary_agent_id: primaryAgentId || undefined,
  });
}

export function closeInvestigationWorkspace(workspaceId: number) {
  return apiPost<InvestigationWorkspace>(`/api/investigations/workspaces/${workspaceId}/close`);
}

export function reopenInvestigationWorkspace(workspaceId: number) {
  return apiPost<InvestigationWorkspace>(`/api/investigations/workspaces/${workspaceId}/reopen`);
}

export function listInvestigationNotes(workspaceId: number, params?: { limit?: number }) {
  const q = new URLSearchParams();
  q.set("limit", String(params?.limit ?? 200));
  return apiGet<InvestigationNote[]>(`/api/investigations/workspaces/${workspaceId}/notes?${q.toString()}`);
}

export function createInvestigationNote(workspaceId: number, body: string) {
  return apiPost<InvestigationNote>(`/api/investigations/workspaces/${workspaceId}/notes`, { body });
}

export function updateInvestigationNote(noteId: number, body: string) {
  return apiPut<InvestigationNote>(`/api/investigations/notes/${noteId}`, { body });
}

export function deleteInvestigationNote(noteId: number) {
  return apiDelete<{ status: string; note_id: number }>(`/api/investigations/notes/${noteId}`);
}

export function listInvestigationBookmarks(workspaceId: number, params?: { evidence_type?: string; page_size?: number; cursor?: string | null }) {
  const q = new URLSearchParams();
  q.set("page_size", String(params?.page_size ?? 100));
  if (params?.evidence_type) q.set("evidence_type", params.evidence_type);
  if (params?.cursor) q.set("cursor", params.cursor);
  return apiGet<InvestigationBookmarksPage>(`/api/investigations/workspaces/${workspaceId}/bookmarks?${q.toString()}`);
}

export function createInvestigationBookmark(workspaceId: number, payload: InvestigationBookmarkCreateIn) {
  return apiPost<InvestigationBookmarkCreateResult>(`/api/investigations/workspaces/${workspaceId}/bookmarks`, payload);
}

export function deleteInvestigationBookmark(bookmarkId: number) {
  return apiDelete<{ status: string; bookmark_id: number }>(`/api/investigations/bookmarks/${bookmarkId}`);
}

function withPinDefaults(payload?: InvestigationPinOptions): InvestigationPinOptions {
  return {
    source_module: payload?.source_module,
    evidence_subtype: payload?.evidence_subtype,
    note: payload?.note,
    tags: payload?.tags || [],
    metadata: payload?.metadata || {},
  };
}

export function pinEventToWorkspace(workspaceId: number, eventId: number, payload?: InvestigationPinOptions) {
  return apiPost<InvestigationBookmarkCreateResult>(
    `/api/investigations/workspaces/${workspaceId}/pin-event/${eventId}`,
    withPinDefaults(payload)
  );
}

export function pinProtocolIntelEventToWorkspace(workspaceId: number, eventId: number, payload?: InvestigationPinOptions) {
  return apiPost<InvestigationBookmarkCreateResult>(
    `/api/investigations/workspaces/${workspaceId}/pin-protocol-intel-event/${eventId}`,
    withPinDefaults(payload)
  );
}

export function pinInventorySnapshotToWorkspace(workspaceId: number, snapshotId: number, payload?: InvestigationPinOptions) {
  return apiPost<InvestigationBookmarkCreateResult>(
    `/api/investigations/workspaces/${workspaceId}/pin-inventory-snapshot/${snapshotId}`,
    withPinDefaults(payload)
  );
}

export function pinResponseResultToWorkspace(workspaceId: number, resultId: number, payload?: InvestigationPinOptions) {
  return apiPost<InvestigationBookmarkCreateResult>(
    `/api/investigations/workspaces/${workspaceId}/pin-response-result/${resultId}`,
    withPinDefaults(payload)
  );
}

export function pinAttackChainCaseToWorkspace(workspaceId: number, caseId: number, payload?: InvestigationPinOptions) {
  return apiPost<InvestigationBookmarkCreateResult>(
    `/api/investigations/workspaces/${workspaceId}/pin-attack-chain-case/${caseId}`,
    withPinDefaults(payload)
  );
}

export function pinAttackChainStepToWorkspace(workspaceId: number, stepId: number, payload?: InvestigationPinOptions) {
  return apiPost<InvestigationBookmarkCreateResult>(
    `/api/investigations/workspaces/${workspaceId}/pin-attack-chain-step/${stepId}`,
    withPinDefaults(payload)
  );
}
