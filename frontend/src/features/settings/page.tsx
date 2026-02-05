import { useMemo, useState } from "react";

import { Card } from "@/shared/components/Card";
import { authApi } from "@/shared/lib/http";
import { useAuth } from "@/features/auth/context";

function fmtSeconds(s: number): string {
  if (!Number.isFinite(s) || s <= 0) return "-";
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r ? `${m}m ${r}s` : `${m}m`;
}

export default function SettingsPage() {
  const { user } = useAuth();
  const isAdmin = (user?.role || "").toLowerCase() === "admin";

  const [label, setLabel] = useState("portal-access");
  const [username, setUsername] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [expiresIn, setExpiresIn] = useState<number | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const tokenMasked = useMemo(() => {
    if (!token) return "";
    if (token.length <= 16) return token;
    return `${token.slice(0, 10)}…${token.slice(-6)}`;
  }, [token]);

  async function createOtp() {
    if (!isAdmin || isBusy) return;
    setIsBusy(true);
    setError(null);
    setCopied(false);

    try {
      const res = await authApi.otpCreate({
        label: (label || "").trim() || undefined,
        username: (username || "").trim() || undefined,
      });
      setToken(res.token);
      setExpiresIn(res.expires_in);
    } catch (e: any) {
      setError(e?.message || "Falha ao gerar token");
      setToken(null);
      setExpiresIn(null);
    } finally {
      setIsBusy(false);
    }
  }

  async function copyToken() {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore
    }
  }

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="text-muted-foreground">Configurações do portal.</p>
      </div>

      <Card
        title="One-time login token"
        right={isAdmin ? "admin" : "restricted"}
        className="max-w-2xl"
      >
        {!isAdmin ? (
          <div className="text-sm text-muted-foreground">
            Somente <span className="font-mono">admin</span> pode gerar tokens de uso único.
          </div>
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Label</label>
                <input
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                  placeholder="portal-access"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Username (optional)</label>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
                  placeholder="admin"
                />
              </div>
            </div>

            {error && (
              <div className="border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">
                {error}
              </div>
            )}

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={createOtp}
                disabled={isBusy}
                className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/40 px-4 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60 disabled:opacity-60"
              >
                {isBusy ? "Generating…" : "Generate"}
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
                  Expires in <span className="font-mono">{fmtSeconds(expiresIn ?? 0)}</span>. Single-use.
                  Share via a secure channel.
                </div>
                <div className="text-[11px] text-muted-foreground opacity-70">Preview: <span className="font-mono">{tokenMasked}</span></div>
              </div>
            ) : (
              <div className="text-[11px] text-muted-foreground">
                Use isto para fornecer acesso temporário sem senha. O usuário entra em <span className="font-mono">/login</span> → <span className="font-mono">One‑time Token</span>.
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
