import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "@/features/auth/context";
import Loading from "@/shared/components/Loading";

type Mode = "password" | "otp";

function safeNextPath(raw: any): string {
  const p = typeof raw === "string" ? raw : "";
  if (!p.startsWith("/")) return "/overview";
  // prevent redirect to login loop
  if (p.startsWith("/login")) return "/overview";
  return p;
}

export default function LoginPage() {
  const { status, otpEnabled, loginWithPassword, loginWithOtp } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();

  const next = useMemo(() => safeNextPath((loc.state as any)?.from?.pathname), [loc.state]);

  const [mode, setMode] = useState<Mode>("password");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!otpEnabled && mode === "otp") setMode("password");
  }, [otpEnabled, mode]);

  useEffect(() => {
    if (status === "authed") {
      nav(next, { replace: true });
    }
  }, [status, nav, next]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (isSubmitting) return;

    setIsSubmitting(true);
    setError(null);

    try {
      if (mode === "password") {
        await loginWithPassword(username.trim(), password);
      } else {
        await loginWithOtp(otp.trim());
      }
    } catch (err: any) {
      setError(err?.message || "Authentication failed");
    } finally {
      setIsSubmitting(false);
    }
  }

  // If we're still restoring session, keep the UI quiet.
  if (status === "loading") {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <Loading label="Restoring session" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="border border-border/60 bg-card/10 backdrop-blur-md">
          <div className="border-b border-border/60 bg-muted/10 px-5 py-4">
            <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Seagull Portal</div>
            <div className="text-lg font-semibold mt-1">Sign in</div>
          </div>

          <div className="p-5 space-y-4">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setMode("password")}
                className={
                  "flex-1 h-9 border text-[10px] font-mono uppercase tracking-widest " +
                  (mode === "password"
                    ? "border-primary/60 bg-primary/10 text-primary"
                    : "border-border/60 bg-background/40 hover:bg-background/60")
                }
              >
                Password
              </button>
              {otpEnabled ? (
                <button
                  type="button"
                  onClick={() => setMode("otp")}
                  className={
                    "flex-1 h-9 border text-[10px] font-mono uppercase tracking-widest " +
                    (mode === "otp"
                      ? "border-primary/60 bg-primary/10 text-primary"
                      : "border-border/60 bg-background/40 hover:bg-background/60")
                  }
                >
                  One-time Token
                </button>
              ) : null}
            </div>

            {error && (
              <div className="border border-danger/40 bg-danger/10 px-3 py-2 text-xs font-mono text-danger">
                {error}
              </div>
            )}

            <form onSubmit={onSubmit} className="space-y-3">
              {mode === "password" ? (
                <>
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Username</label>
                    <input
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                      className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                      placeholder="admin"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Password</label>
                    <input
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      type="password"
                      autoComplete="current-password"
                      className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                      placeholder="••••••••"
                    />
                  </div>
                </>
              ) : (
                <>
                  <div className="space-y-1">
                    <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">One‑time Token</label>
                    <input
                      value={otp}
                      onChange={(e) => setOtp(e.target.value)}
                      autoComplete="off"
                      className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60 font-mono"
                      placeholder="nw_otp_..."
                    />
                    <div className="text-[11px] text-muted-foreground">
                      Tokens are single‑use and expire. Ask an admin to generate one in <span className="font-mono">Settings</span>.
                    </div>
                  </div>
                </>
              )}

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full h-10 border border-border/60 bg-background/40 hover:bg-background/60 text-[10px] font-mono uppercase tracking-widest disabled:opacity-60"
              >
                {isSubmitting ? "Signing in..." : "Sign in"}
              </button>
            </form>

            <div className="text-[11px] text-muted-foreground">
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
