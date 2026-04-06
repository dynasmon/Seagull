import type { CursorPage } from "@/shared/types/pagination";

export type InvestigationWorkspaceStatus = "open" | "contained" | "resolved" | "closed";
export type InvestigationWorkspaceSeverity = "low" | "medium" | "high" | "critical";
export type InvestigationWorkspacePriority = "p1" | "p2" | "p3" | "p4";
export type InvestigationWorkspaceTriage = "untriaged" | "triage" | "assigned" | "investigating" | "contained" | "closed";

export type InvestigationEvidenceType =
  | "net_event"
  | "protocol_intel"
  | "inventory_snapshot"
  | "response_action_result"
  | "attack_chain_case"
  | "attack_chain_step";

export type InvestigationWorkspace = {
  id: number;
  workspace_key: string;
  title: string;
  description: string | null;
  status: InvestigationWorkspaceStatus;
  severity: InvestigationWorkspaceSeverity;
  priority: InvestigationWorkspacePriority;
  triage_state: InvestigationWorkspaceTriage;
  assignee: string | null;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  linked_attack_chain_case_id: number | null;
  primary_agent_id: string | null;
  summary: Record<string, unknown>;
  notes_count: number;
  bookmarks_count: number;
  evidence_type_counts: Record<string, number>;
};

export type InvestigationNote = {
  id: number;
  workspace_id: number;
  author: string;
  body: string;
  created_at: string;
  updated_at: string;
  edited: boolean;
};

export type InvestigationBookmark = {
  id: number;
  workspace_id: number;
  evidence_type: InvestigationEvidenceType;
  evidence_subtype: string | null;
  source_module: string;
  title: string;
  summary: string | null;
  agent_id: string | null;
  observed_at: string | null;
  created_by: string;
  created_at: string;
  ref_id: string | null;
  ref_table: string | null;
  fingerprint: string | null;
  tags: string[];
  payload_snapshot: Record<string, unknown>;
  metadata: Record<string, unknown>;
};

export type InvestigationBookmarkCreateResult = {
  created: boolean;
  duplicate_of_id: number | null;
  bookmark: InvestigationBookmark;
};

export type InvestigationActivityType =
  | "workspace_created"
  | "workspace_updated"
  | "workspace_closed"
  | "workspace_reopened"
  | "note_created"
  | "note_updated"
  | "bookmark_created"
  | "bookmark_deleted"
  | "attack_chain_case_linked"
  | "attack_chain_step_pinned"
  | "workspace_action";

export type InvestigationActivityEntry = {
  id: string;
  workspace_id: number;
  activity_type: InvestigationActivityType;
  action: string;
  actor_username: string | null;
  created_at: string;
  outcome: string;
  target_type: string | null;
  target_id: string | null;
  summary: string;
  changed_fields: string[];
  context: Record<string, unknown>;
};

export type InvestigationPinOptions = {
  source_module?: string;
  evidence_subtype?: string;
  note?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
};

export type InvestigationWorkspaceCreateIn = {
  title: string;
  description?: string;
  status?: InvestigationWorkspaceStatus;
  severity?: InvestigationWorkspaceSeverity;
  priority?: InvestigationWorkspacePriority;
  triage_state?: InvestigationWorkspaceTriage;
  assignee?: string;
  linked_attack_chain_case_id?: number;
  primary_agent_id?: string;
  initial_note?: string;
};

export type InvestigationWorkspaceUpdateIn = {
  title?: string;
  description?: string;
  status?: InvestigationWorkspaceStatus;
  severity?: InvestigationWorkspaceSeverity;
  priority?: InvestigationWorkspacePriority;
  triage_state?: InvestigationWorkspaceTriage;
  assignee?: string | null;
  linked_attack_chain_case_id?: number | null;
  primary_agent_id?: string | null;
};

export type InvestigationBookmarkCreateIn = InvestigationPinOptions & {
  evidence_type: InvestigationEvidenceType;
  source_event_id?: number;
  inventory_snapshot_id?: number;
  response_action_result_id?: number;
  attack_chain_case_id?: number;
  attack_chain_step_id?: number;
};

export type InvestigationWorkspacePage = CursorPage<InvestigationWorkspace>;
export type InvestigationBookmarksPage = CursorPage<InvestigationBookmark>;
export type InvestigationActivityPage = CursorPage<InvestigationActivityEntry>;
