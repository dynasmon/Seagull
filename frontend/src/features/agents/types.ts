export type AgentPublic = {
  agent_id: string;
  display_name?: string | null;
  description?: string | null;
  tags: string[];
  created_at: string;
  last_seen_at?: string | null;
  is_revoked: boolean;
  metadata: Record<string, any>;
  metrics: Record<string, any>;
};

export type AgentDetail = AgentPublic & {
  config: Record<string, any>;
};

export type AgentUpdateIn = {
  display_name?: string | null;
  description?: string | null;
  tags?: string[] | null;
  metadata?: Record<string, any> | null;
};

export type ResponseActionCreateIn = {
  action_type: string;
  agent_id: string;
  payload?: Record<string, any>;
  expires_at?: string;
};

export type ResponseActionOut = {
  id: number;
  action_type: string;
  agent_id: string;
  status: string;
  payload: Record<string, any>;
  requested_by: string;
  requested_at: string;
  delivered_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  cancelled_at?: string | null;
  cancelled_by?: string | null;
  last_error?: string | null;
  created_at: string;
  updated_at: string;
  expires_at?: string | null;
};

export type ResponseActionResultOut = {
  id: number;
  response_action_id: number;
  agent_id: string;
  status: string;
  result_payload: Record<string, any>;
  error?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
  updated_at: string;
};
