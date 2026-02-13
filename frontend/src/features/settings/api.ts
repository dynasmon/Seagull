import { apiGet, apiPost } from "@/shared/lib/http";

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
