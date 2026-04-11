import { useMemo, useState } from "react";

import { Card } from "@/shared/components/Card";
import PageHeader from "@/shared/components/PageHeader";
import { useAuth } from "@/features/auth/context";

import { changeMyPassword } from "./api";

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

export default function SettingsPage() {
  const { user, logout } = useAuth();

  const [curPw, setCurPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");

  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwOk, setPwOk] = useState<string | null>(null);

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

  async function doChangePassword() {
    if (pwBusy) return;

    setPwError(null);
    setPwOk(null);

    if (!canSubmit) {
      setPwError("Password policy is not correct.");
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
    } catch (e: any) {
      setPwError(e?.message || "Failed to change password");
    } finally {
      setPwBusy(false);
    }
  }

  function RuleRow({ ok, label }: { ok: boolean; label: string }) {
    return (
      <div className="flex items-center gap-2 text-[11px]">
        <span
          className={
            "inline-block h-2.5 w-2.5 rounded-full " + (ok ? "bg-emerald-400" : "bg-muted-foreground/40")
          }
        />
        <span className={ok ? "text-foreground" : "text-muted-foreground"}>{label}</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        breadcrumb={["Account"]}
        description="Manage account security settings."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
        <Card title="Account" className="w-full rounded-xl">
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-muted-foreground">Username:</span>{" "}
              <span className="font-mono">{user?.username || "-"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Role:</span>{" "}
              <span className="font-mono">{user?.role || "-"}</span>
            </div>
            <div className="text-[11px] text-muted-foreground pt-2">
              Keep your credentials unique. Password changes revoke active refresh sessions and tokens.
            </div>
          </div>
        </Card>

        <Card title="Session" className="w-full rounded-xl">
          <div className="space-y-3">
            <div className="text-[11px] text-muted-foreground">Sign out from the current session.</div>
            <button
              type="button"
              onClick={() => logout()}
              className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/40 px-4 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60"
            >
              Sign out
            </button>
          </div>
        </Card>

        <div className="lg:col-span-2">
          <Card title="Change password" right={user ? user.username : "-"} className="w-full rounded-xl">
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="space-y-1 md:col-span-2">
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

                <div className="space-y-1">
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

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 rounded-lg border border-border/60 bg-background/20 p-3">
                <RuleRow ok={policy.minLen} label="At least 12 characters" />
                <RuleRow ok={policy.upper} label="Contains uppercase letter" />
                <RuleRow ok={policy.lower} label="Contains lowercase letter" />
                <RuleRow ok={policy.digit} label="Contains digit" />
                <RuleRow ok={policy.symbol} label="Contains symbol" />
                <RuleRow ok={policy.noSpaces} label="No spaces" />
                <RuleRow ok={policy.noUsername} label="Does not include username" />
                <RuleRow ok={policy.confirmMatch} label="Confirmation matches" />
              </div>

              {pwError ? (
                <div className="border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">{pwError}</div>
              ) : null}

              {pwOk ? (
                <div className="border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs font-mono text-emerald-200">{pwOk}</div>
              ) : null}

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={doChangePassword}
                  disabled={pwBusy || !canSubmit}
                  className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/40 px-4 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60 disabled:opacity-60"
                >
                  {pwBusy ? "Updating…" : "Update password"}
                </button>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
