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
};

export const PAYLOAD_TEMPLATES: Record<string, Record<string, any>> = {
  collect_triage_bundle: {},
  trigger_inventory_snapshot: {},
  refresh_runtime_config: {},
  trigger_topology_discovery: {},
  kill_process: { target: { pid: 0 }, signal: "SIGTERM", dry_run: true },
  block_outbound_ip: { ip: "", protocol: "tcp", dry_run: true },
  unblock_outbound_ip: { ip: "", protocol: "tcp" },
  quarantine_file: { path: "", compute_hash: true, dry_run: true },
  run_shell_command: { command: "", timeout_seconds: 30 },
};
