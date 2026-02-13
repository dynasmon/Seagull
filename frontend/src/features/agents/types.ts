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
