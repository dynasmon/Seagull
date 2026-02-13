import { useEffect, useMemo, useState } from "react";

import { Card } from "@/shared/components/Card";
import { authApi } from "@/shared/lib/http";
import { useAuth } from "@/features/auth/context";
import { changeMyPassword, getAdminLoginHistory, type AdminLoginEvent } from "./api";

/**
 * Formats a duration in seconds into a short human-friendly string.
 */
function fmtSeconds(s: number): string {
  if (!Number.isFinite(s) || s <= 0) return "-";
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r ? `${m}m ${r}s` : `${m}m`;
}

/**
 * Formats an ISO timestamp (UTC) into a local date-time string.
 */
function fmtWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  // One-time token (existing)
  const [label, setLabel] = useState("portal-access");
  const [username, setUsername] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<number | null>(null);
  const [isBusyOtp, setIsBusyOtp] = useState(false);
  const [otpError, setOtpError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Password change (new)
  const [curPw, setCurPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwOk, setPwOk] = useState<string | null>(null);

  // Admin login history (new)
  const [hist, setHist] = useState<AdminLoginEvent[]>([]);
  const [histBusy, setHistBusy] = useState(false);
  const [histError, setHistError] = useState<string | null>(null);

  const tokenMasked = useMemo(() => {
    if (!token) return "";
    if (token.length <= 16) return token;
    return `${token.slice(0, 10)}…${token.slice(-6)}`;
  }, [token]);

  async function createOtp() {
    if (!isAdmin || isBusyOtp) return;
    setIsBusyOtp(true);
    setOtpError(null);
    setCopied(false);

    try {
      const res = await authApi.otpCreate({
        label: (label || "").trim() || undefined,
        username: (username || "").trim() || undefined
      });
      setToken(res.token);
      setExpiresIn(res.expires_in);
    } catch (e: any) {
      setOtpError(e?.message || "Failed to generate token");
      setToken(null);
      setExpiresIn(null);
    } finally {
      setIsBusyOtp(false);
    }
  }

  async function copyToken() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // Intentionally ignored: clipboard permission can be denied by the browser.
    }
  }

  async function doChangePassword() {
    if (pwBusy) return;
    setPwOk(null);
    setPwError(null);

    const a = curPw;
    const b = newPw;
    const c = newPw2;

    if (!a || !b || !c) {
      setPwError("Please fill in all fields.");
      return;
    }
    if (b !== c) {
      setPwError("Confirmation does not match.");
      return;
    }

    setPwBusy(true);
    try {
      await changeMyPassword(a, b);
      setPwOk("Password updated. Please sign in again.");
      setCurPw("");
      setNewPw("");
      setNewPw2("");
      // Backend revokes refresh sessions. Also terminate the portal session locally.
      await logout();
    } catch (e: any) {
      setPwError(e?.message || "Failed to change password");
    } finally {
      setPwBusy(false);
    }
  }

  async function loadLoginHistory() {
    if (!isAdmin || histBusy) return;
    setHistBusy(true);
    setHistError(null);
    try {
      const rows = await getAdminLoginHistory(25, false);
      setHist(rows);
    } catch (e: any) {
      setHistError(e?.message || "Failed to load history");
      setHist([]);
    } finally {
      setHistBusy(false);
    }
  }

  useEffect(() => {
    loadLoginHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin]);

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="text-muted-foreground">Portal configuration and security.</p>
      </div>

      <Card title="Change password" right={user ? user.username : "anon"} className="max-w-2xl">
        <div className="space-y-3">
          <div className="text-[11px] text-muted-foreground">
            For security, changing your password revokes all sessions (refresh tokens) and requires a new sign-in.
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Current password
              </label>
              <input
                value={curPw}
                onChange={(e) => setCurPw(e.target.value)}
                type="password"
                autoComplete="current-password"
                className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                placeholder="••••••••••••"
              />
            </div>

            <div className="space-y-1">
              <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                New password
              </label>
              <input
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                type="password"
                autoComplete="new-password"
                className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                placeholder="Min 12 chars"
              />
            </div>

            <div className="space-y-1 md:col-span-2">
              <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Confirm new password
              </label>
              <input
                value={newPw2}
                onChange={(e) => setNewPw2(e.target.value)}
                type="password"
                autoComplete="new-password"
                className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                placeholder="Repeat new password"
              />
            </div>
          </div>

          <div className="text-[11px] text-muted-foreground">
            Policy: 12+ chars, upper + lower + digit + symbol, no spaces, must not contain your username, must not
            repeat the current password.
          </div>

          {pwError && (
            <div className="border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">
              {pwError}
            </div>
          )}

          {pwOk && (
            <div className="border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs font-mono text-emerald-200">
              {pwOk}
            </div>
          )}

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={doChangePassword}
              disabled={pwBusy}
              className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/40 px-4 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60 disabled:opacity-60"
            >
              {pwBusy ? "Updating…" : "Update password"}
            </button>
          </div>
        </div>
      </Card>

      <Card title="One-time login token" right={isAdmin ? "admin" : "restricted"} className="max-w-2xl">
        {!isAdmin ? (
          <div className="text-sm text-muted-foreground">
            Only <span className="font-mono">admin</span> can generate one-time tokens.
          </div>
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                  Label
                </label>
                <input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                  placeholder="portal-access"
                />
              </div>

              <div className="space-y-1">
                <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                  Username (optional)
                </label>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                  placeholder="admin"
                />
              </div>
            </div>

            {otpError && (
              <div className="border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">
                {otpError}
              </div>
            )}

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={createOtp}
                disabled={isBusyOtp}
                className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/40 px-4 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60 disabled:opacity-60"
              >
                {isBusyOtp ? "Generating…" : "Generate"}
              </button>

              {token && (
                <button
                  type="button"
                  onClick={copyToken}
                  className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/40 px-4 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60"
                >
                  {copied ? "Copied" : "Copy"}
                </button>
              )}
            </div>

            {token ? (
              <div className="space-y-1">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                  Token (shown once — copy now)
                </div>
                <div className="border border-border/60 bg-background/40 px-3 py-2 font-mono text-xs break-all">
                  {token}
                </div>
                <div className="text-[11px] text-muted-foreground">
                  Expires in <span className="font-mono">{fmtSeconds(expiresIn ?? 0)}</span>. Single-use. Share via a
                  secure channel.
                </div>
                <div className="text-[11px] text-muted-foreground opacity-70">
                  Preview: <span className="font-mono">{tokenMasked}</span>
                </div>
              </div>
            ) : (
              <div className="text-[11px] text-muted-foreground">
                Use this to provide temporary access without a password. The user signs in at{" "}
                <span className="font-mono">/login</span> → <span className="font-mono">One-time Token</span>.
              </div>
            )}
          </div>
        )}
      </Card>

      {isAdmin && (
        <Card title="Recent admin logins" right={histBusy ? "loading" : `${hist.length} events`} className="max-w-3xl">
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="text-[11px] text-muted-foreground">
                Latest sign-ins for <span className="font-mono">admin</span> accounts (basic auditing).
              </div>
              <button
                type="button"
                onClick={loadLoginHistory}
                disabled={histBusy}
                className="inline-flex h-9 items-center justify-center border border-border/60 bg-background/40 px-3 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60 disabled:opacity-60"
              >
                Refresh
              </button>
            </div>

            {histError && (
              <div className="border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">
                {histError}
              </div>
            )}

            <div className="overflow-auto border border-border/60">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/10">
                  <tr className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                    <th className="px-3 py-2">When</th>
                    <th className="px-3 py-2">User</th>
                    <th className="px-3 py-2">Method</th>
                    <th className="px-3 py-2">IP</th>
                    <th className="px-3 py-2">UA</th>
                  </tr>
                </thead>
                <tbody>
                  {hist.map((r, idx) => (
                    <tr key={idx} className="border-t border-border/60">
                      <td className="px-3 py-2 whitespace-nowrap">{fmtWhen(r.created_at)}</td>
                      <td className="px-3 py-2 font-mono">{r.username}</td>
                      <td className="px-3 py-2 font-mono">{r.method}</td>
                      <td className="px-3 py-2 font-mono">{r.ip || "-"}</td>
                      <td className="px-3 py-2 max-w-[360px] truncate font-mono opacity-80">
                        {r.user_agent || "-"}
                      </td>
                    </tr>
                  ))}

                  {!hist.length && (
                    <tr className="border-t border-border/60">
                      <td className="px-3 py-3 text-muted-foreground" colSpan={5}>
                        No events yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="text-[11px] text-muted-foreground">
              Note: the backend records IP/UA on a best-effort basis (a failed insert will not break sign-in).
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
