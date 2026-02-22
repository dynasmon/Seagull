import { apiDelete, apiGet, apiPost, apiPut } from "@/shared/lib/http";

export type AdminLoginEvent = {
  created_at: string;
  username: string;
  method: string;
  ip: string | null;
  user_agent: string | null;
  succeeded: boolean;
};

export function getAdminLoginHistory(limit = 20, includeFailed = false) {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  if (includeFailed) params.set("include_failed", "true");
  return apiGet<AdminLoginEvent[]>(`/api/admin/login-history?${params.toString()}`);
}

export function changeMyPassword(currentPassword: string, newPassword: string) {
  return apiPost<void>("/api/account/change-password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
}

export type AttackChainAllowlistRule = {
  id: number;
  rule_type: string;
  enabled: boolean;
  match_mode: "exact" | "prefix" | "contains" | string;
  pattern: string;
  agent_id: string | null;
  username: string | null;
  target_user: string | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
};

export function listAttackChainAllowlist() {
  return apiGet<AttackChainAllowlistRule[]>("/api/attack-chain/allowlist?rule_type=sudo_cmd");
}

export function createAttackChainAllowlistRule(payload: {
  enabled: boolean;
  match_mode: "exact" | "prefix" | "contains";
  pattern: string;
  agent_id?: string;
  username?: string;
  target_user?: string;
  notes?: string;
}) {
  return apiPost<AttackChainAllowlistRule>("/api/attack-chain/allowlist", payload);
}

export function updateAttackChainAllowlistRule(ruleId: number, payload: Partial<{
  enabled: boolean;
  match_mode: "exact" | "prefix" | "contains";
  pattern: string;
  agent_id: string | null;
  username: string | null;
  target_user: string | null;
  notes: string | null;
}>) {
  return apiPut<AttackChainAllowlistRule>(`/api/attack-chain/allowlist/${ruleId}`, payload);
}

export function deleteAttackChainAllowlistRule(ruleId: number) {
  return apiDelete<{ status: string; deleted: boolean; id: number }>(`/api/attack-chain/allowlist/${ruleId}`);
}
