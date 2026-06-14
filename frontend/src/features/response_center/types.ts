import type {
  ResponseActionCreateIn,
  ResponseActionOut,
  ResponseActionResultOut,
} from "@/features/agents/types";

export type { ResponseActionCreateIn, ResponseActionOut, ResponseActionResultOut };

export type ActionCategory = "forensics" | "diagnostics" | "containment";
export type ActionRiskLevel = "low" | "medium" | "high" | "critical";

export type ActionTypeOut = {
  key: string;
  label: string;
  category: ActionCategory;
  risk_level: ActionRiskLevel;
  reversible: boolean;
  requires_confirmation: boolean;
  estimated_duration_seconds: number;
  undo_action: string | null;
  description: string;
  payload_template: Record<string, any>;
};

export type TimelineEventOut = {
  at: string;
  event: string;
  actor: string;
  detail?: string | null;
};

export type BatchQueuedItem = {
  agent_id: string;
  action_id: number;
};

export type BatchSkippedItem = {
  agent_id: string;
  reason: string;
};

export type BatchDispatchIn = {
  action_type: string;
  agent_ids: string[];
  payload?: Record<string, any>;
  expires_at?: string;
  justification?: string;
};

export type BatchDispatchOut = {
  batch_id: string;
  total: number;
  queued: BatchQueuedItem[];
  skipped: BatchSkippedItem[];
};

export type ResponseActionListParams = {
  agent_id?: string;
  agent_ids?: string[];
  status?: string;
  category?: string;
  risk_level?: string;
  batch_id?: string;
  since?: string;
  limit?: number;
};

export type ExecutionFilters = {
  statuses: string[];
  category: string;
  agentId: string;
  since: string;
  batchId: string;
};
