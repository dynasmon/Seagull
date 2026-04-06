import type { QueryProvenanceMeta } from "../../types";

export type SshIpStat = {
  src_ip: string;
  count: number;
  geo_country?: string | null;
  geo_org?: string | null;
  asn?: string | null;
  asn_org?: string | null;
};

export type SshUserStat = {
  username: string;
  count: number;
};

export type SshLoginEvent = {
  timestamp: string;
  agent_id: string;
  src_ip?: string | null;
  username?: string | null;
  geo_country?: string | null;
  geo_org?: string | null;
  asn?: string | null;
  asn_org?: string | null;
};

export type SshAuthEvent = {
  timestamp: string;
  agent_id: string;
  action?: string | null;
  src_ip?: string | null;
  username?: string | null;
  geo_country?: string | null;
  geo_org?: string | null;
  asn?: string | null;
  asn_org?: string | null;
};

export type SudoEventSummary = {
  timestamp: string;
  agent_id: string;
  username?: string | null;
  target_user?: string | null;
  command?: string | null;
  tty?: string | null;
  pwd?: string | null;
};

export type SshSummaryResponse = {
  generated_at: string;
  since_minutes: number;
  agent_id?: string | null;
  total_accepted: number;
  total_failed_password: number;
  total_invalid_user: number;
  total_actions: number;
  unique_source_ips: number;
  enriched_source_ips: number;
  recent_auth_events: SshAuthEvent[];
  successful_logins: SshIpStat[];
  failed_attempts: SshIpStat[];
  invalid_user_attempts: SshIpStat[];
  most_active_ips: SshIpStat[];
  root_logins: SshLoginEvent[];
  users_attempted: SshUserStat[];
  sudo_recent: SudoEventSummary[];
  meta?: QueryProvenanceMeta | null;
};
