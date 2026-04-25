import { useEffect, useMemo, useState } from "react";

import { useAuth } from "@/features/auth/context";
import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { Card } from "@/shared/components/Card";
import { InlineAlert } from "@/shared/components/InlineAlert";
import Loading from "@/shared/components/Loading";
import PageHeader from "@/shared/components/PageHeader";
import { Table } from "@/shared/components/Table";
import { TextInput } from "@/shared/components/TextInput";

import { changeMyPassword, getAdminLoginHistory, getRuntimeConfig, type AdminLoginEvent } from "./api";

function hasUpper(s: string): boolean {
  return /[A-Z]/.test(s);
}

function hasLower(s: string): boolean {
  return /[a-z]/.test(s);
}

function hasDigit(s: string): boolean {
  return /\d/.test(s);
}

function hasSymbol(s: string): boolean {
  return /[^A-Za-z0-9\s]/.test(s);
}

function hasNoSpaces(s: string): boolean {
  return !/\s/.test(s);
}

function fmtDateTime(value: string | null | undefined): string {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function PasswordRule({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2 text-[12px]">
      <span className={ok ? "inline-block h-2.5 w-2.5 rounded-full bg-success" : "inline-block h-2.5 w-2.5 rounded-full bg-muted-foreground/40"} />
      <span className={ok ? "text-foreground" : "text-muted-foreground"}>{label}</span>
    </div>
  );
}

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const isAdmin = String(user?.role || "").toLowerCase() === "admin";

  const [curPw, setCurPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwOk, setPwOk] = useState<string | null>(null);

  const [loginRows, setLoginRows] = useState<AdminLoginEvent[]>([]);
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [runtimeSecurity, setRuntimeSecurity] = useState<Record<string, any> | null>(null);
  const [runtimeBusy, setRuntimeBusy] = useState(false);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);

  const username = String(user?.username || "").trim().toLowerCase();

  const policy = useMemo(() => {
    const candidate = newPw || "";
    const noUsername = username ? !candidate.toLowerCase().includes(username) : true;
    return {
      minLen: candidate.length >= 12,
      upper: hasUpper(candidate),
      lower: hasLower(candidate),
      digit: hasDigit(candidate),
      symbol: hasSymbol(candidate),
      noSpaces: hasNoSpaces(candidate),
      noUsername,
      confirmMatch: candidate.length > 0 && candidate === newPw2,
      changed: candidate.length > 0 && candidate !== curPw,
    };
  }, [newPw, newPw2, curPw, username]);

  const canSubmit =
    !!curPw &&
    !!newPw &&
    !!newPw2 &&
    policy.minLen &&
    policy.upper &&
    policy.lower &&
    policy.digit &&
    policy.symbol &&
    policy.noSpaces &&
    policy.noUsername &&
    policy.confirmMatch &&
    policy.changed;

  const failedLoginCount = useMemo(() => loginRows.filter((row) => !row.succeeded).length, [loginRows]);
  const lastSuccessfulLogin = useMemo(() => {
    const found = loginRows.find((row) => row.succeeded);
    return found ? fmtDateTime(found.created_at) : "-";
  }, [loginRows]);

  useEffect(() => {
    if (!isAdmin) return;
    let alive = true;

    async function loadContext() {
      setLoginBusy(true);
      setRuntimeBusy(true);
      setLoginError(null);
      setRuntimeError(null);

      try {
        const [history, runtime] = await Promise.all([
          getAdminLoginHistory(25, true),
          getRuntimeConfig(),
        ]);
        if (!alive) return;
        setLoginRows(Array.isArray(history) ? history : []);
        setRuntimeSecurity((runtime?.config?.security || {}) as Record<string, any>);
      } catch (error: any) {
        if (!alive) return;
        setLoginRows([]);
        setRuntimeSecurity(null);
        setLoginError(error?.message || "Failed to load login activity");
        setRuntimeError(error?.message || "Failed to load runtime security policy");
      } finally {
        if (!alive) return;
        setLoginBusy(false);
        setRuntimeBusy(false);
      }
    }

    void loadContext();
    return () => {
      alive = false;
    };
  }, [isAdmin]);

  async function doChangePassword() {
    if (pwBusy) return;

    setPwError(null);
    setPwOk(null);

    if (!canSubmit) {
      setPwError("Password policy is not satisfied.");
      return;
    }

    setPwBusy(true);
    try {
      await changeMyPassword(curPw, newPw);
      setPwOk("Password updated. Please sign in again.");
      setCurPw("");
      setNewPw("");
      setNewPw2("");
      await logout();
    } catch (error: any) {
      setPwError(error?.message || "Failed to change password");
    } finally {
      setPwBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        breadcrumb={["Governance & Platform"]}
        description="Manage your account security, password policy, and session activity."
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Account Profile">
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-muted-foreground">Username:</span>{" "}
              <span className="font-mono">{user?.username || "-"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Role:</span>{" "}
              <span className="font-mono">{user?.role || "-"}</span>
            </div>
            <div className="pt-2 text-xs text-muted-foreground">
              Use a unique passphrase and rotate credentials after high-risk incidents.
            </div>
          </div>
        </Card>

        <Card title="Session Controls">
          <div className="space-y-3">
            <div className="text-xs text-muted-foreground">Sign out from the current browser session.</div>
            <Button variant="secondary" size="lg" onClick={() => logout()}>
              Sign out
            </Button>
          </div>
        </Card>

        <Card title="Security Posture" right={isAdmin ? "runtime + activity" : "account scope"}>
          {runtimeBusy ? (
            <Loading label="Loading runtime security policy..." />
          ) : runtimeError && isAdmin ? (
            <InlineAlert tone="danger" className="text-xs">{runtimeError}</InlineAlert>
          ) : (
            <div className="space-y-2 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="neutral">Last successful login: {lastSuccessfulLogin}</Badge>
                <Badge variant={failedLoginCount > 0 ? "medium" : "low"}>Failed attempts: {failedLoginCount}</Badge>
              </div>
              {isAdmin ? (
                <div className="grid grid-cols-2 gap-2 text-[12px]">
                  <div className="rounded border border-border/60 bg-background/30 px-2 py-1">
                    <div className="text-muted-foreground">Password min length</div>
                    <div className="font-mono">{runtimeSecurity?.password_min_length ?? "-"}</div>
                  </div>
                  <div className="rounded border border-border/60 bg-background/30 px-2 py-1">
                    <div className="text-muted-foreground">Session idle timeout</div>
                    <div className="font-mono">
                      {runtimeSecurity?.session_idle_timeout_minutes ? `${runtimeSecurity.session_idle_timeout_minutes}m` : "-"}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          )}
        </Card>
      </div>

      <Card title="Change Password" right={user?.username || "-"}>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void doChangePassword();
          }}
        >
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="space-y-1 md:col-span-2">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Current password</div>
              <TextInput
                value={curPw}
                onChange={(e) => setCurPw(e.target.value)}
                type="password"
                autoComplete="current-password"
                className="h-10"
                placeholder="••••••••••••"
              />
            </label>

            <label className="space-y-1">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">New password</div>
              <TextInput
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                type="password"
                autoComplete="new-password"
                className="h-10"
                placeholder="Minimum 12 characters"
              />
            </label>

            <label className="space-y-1">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Confirm new password</div>
              <TextInput
                value={newPw2}
                onChange={(e) => setNewPw2(e.target.value)}
                type="password"
                autoComplete="new-password"
                className="h-10"
                placeholder="Repeat new password"
              />
            </label>
          </div>

          <div className="grid grid-cols-1 gap-2 rounded-lg border border-border/60 bg-background/20 p-3 md:grid-cols-2">
            <PasswordRule ok={policy.minLen} label="At least 12 characters" />
            <PasswordRule ok={policy.upper} label="Contains uppercase letter" />
            <PasswordRule ok={policy.lower} label="Contains lowercase letter" />
            <PasswordRule ok={policy.digit} label="Contains digit" />
            <PasswordRule ok={policy.symbol} label="Contains symbol" />
            <PasswordRule ok={policy.noSpaces} label="No spaces" />
            <PasswordRule ok={policy.noUsername} label="Does not include username" />
            <PasswordRule ok={policy.confirmMatch} label="Confirmation matches" />
          </div>

          {pwError ? <InlineAlert tone="danger" className="text-xs font-mono">{pwError}</InlineAlert> : null}
          {pwOk ? <InlineAlert tone="success" className="text-xs font-mono">{pwOk}</InlineAlert> : null}

          <div className="flex items-center gap-2">
            <Button type="submit" variant="primary" size="lg" disabled={pwBusy || !canSubmit}>
              {pwBusy ? "Updating..." : "Update password"}
            </Button>
          </div>
        </form>
      </Card>

      {isAdmin ? (
        <Card title="Recent Sign-in Activity" right="/api/admin/login-history">
          {loginBusy ? (
            <Loading label="Loading login activity..." />
          ) : loginError ? (
            <div className="text-sm text-danger">{loginError}</div>
          ) : loginRows.length === 0 ? (
            <div className="text-sm text-muted-foreground">No login activity available in current retention window.</div>
          ) : (
            <Table
              rows={loginRows}
              rowKey={(row, idx) => `${row.created_at}-${row.username}-${idx}`}
              columns={[
                { key: "created_at", title: "When", className: "text-xs font-mono", render: (row) => fmtDateTime(row.created_at) },
                { key: "username", title: "User", className: "text-xs font-mono" },
                { key: "method", title: "Method", className: "text-xs font-mono" },
                { key: "ip", title: "Origin IP", className: "text-xs font-mono", render: (row) => row.ip || "-" },
                {
                  key: "result",
                  title: "Result",
                  className: "text-xs",
                  render: (row) => <Badge variant={row.succeeded ? "low" : "critical"}>{row.succeeded ? "success" : "failed"}</Badge>,
                },
                { key: "user_agent", title: "User agent", className: "text-xs text-muted-foreground", render: (row) => row.user_agent || "-" },
              ]}
            />
          )}
        </Card>
      ) : null}
    </div>
  );
}

