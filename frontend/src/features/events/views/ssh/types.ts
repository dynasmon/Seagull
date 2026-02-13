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
  successful_logins: SshIpStat[];
  failed_attempts: SshIpStat[];
  invalid_user_attempts: SshIpStat[];
  most_active_ips: SshIpStat[];
  root_logins: SshLoginEvent[];
  users_attempted: SshUserStat[];
  sudo_recent: SudoEventSummary[];
};
