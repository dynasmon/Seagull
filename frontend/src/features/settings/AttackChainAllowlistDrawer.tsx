import { useEffect, useMemo, useState } from "react";

import Drawer from "@/shared/components/Drawer";
import { cx } from "@/shared/lib/cx";

import type { AttackChainAllowlistRule } from "./api";
import { createAttackChainAllowlistRule, updateAttackChainAllowlistRule } from "./api";

type Mode = "create" | "edit";

type FormState = {
  enabled: boolean;
  match_mode: "exact" | "prefix" | "contains";
  pattern: string;
  agent_id: string;
  username: string;
  target_user: string;
  notes: string;
};

function toForm(rule: AttackChainAllowlistRule | null): FormState {
  return {
    enabled: rule ? !!rule.enabled : true,
    match_mode: (rule?.match_mode as any) || "contains",
    pattern: rule?.pattern || "",
    agent_id: rule?.agent_id || "",
    username: rule?.username || "",
    target_user: rule?.target_user || "",
    notes: rule?.notes || "",
  };
}

export default function AttackChainAllowlistDrawer({
  open,
  mode,
  rule,
  onClose,
  onSaved,
}: {
  open: boolean;
  mode: Mode;
  rule: AttackChainAllowlistRule | null;
  onClose: () => void;
  onSaved: (row: AttackChainAllowlistRule) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [f, setF] = useState<FormState>(() => toForm(rule));

  useEffect(() => {
    if (!open) return;
    setBusy(false);
    setErr(null);
    setF(toForm(rule));
  }, [open, rule]);

  const canSave = useMemo(() => {
    const p = (f.pattern || "").trim();
    if (!p) return false;
    if (p.length > 512) return false;
    return true;
  }, [f.pattern]);

  async function save() {
    if (busy || !canSave) return;
    setBusy(true);
    setErr(null);

    const payload = {
      enabled: !!f.enabled,
      match_mode: f.match_mode,
      pattern: (f.pattern || "").trim(),
      agent_id: (f.agent_id || "").trim() || undefined,
      username: (f.username || "").trim() || undefined,
      target_user: (f.target_user || "").trim() || undefined,
      notes: (f.notes || "").trim() || undefined,
    };

    try {
      const row =
        mode === "edit" && rule
          ? await updateAttackChainAllowlistRule(rule.id, payload)
          : await createAttackChainAllowlistRule(payload);
      onSaved(row);
    } catch (e: any) {
      setErr(e?.message || "Failed to save allowlist rule");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={mode === "edit" ? "Edit allowlist rule" : "Add allowlist rule"}
      description="Suppress known-benign privileged commands without changing environment variables. Scope rules to reduce blast-radius."
      widthClassName="w-[760px]"
    >
      <div className="space-y-4">
        <div className="text-[11px] text-muted-foreground">
          Matching is performed against a normalized command string (whitespace collapsed). Rules are case-insensitive.
          Use <span className="font-mono">agent_id</span> and <span className="font-mono">username</span> when possible.
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Match mode</label>
            <select
              value={f.match_mode}
              onChange={(e) => setF((s) => ({ ...s, match_mode: e.target.value as any }))}
              className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
            >
              <option value="contains">Contains</option>
              <option value="prefix">Prefix</option>
              <option value="exact">Exact</option>
            </select>
          </div>

          <div className="space-y-1">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Enabled</label>
            <button
              type="button"
              onClick={() => setF((s) => ({ ...s, enabled: !s.enabled }))}
              className={cx(
                "w-full h-10 px-3 border border-border/60",
                "bg-background/40 text-sm outline-none hover:bg-background/60",
                f.enabled ? "text-emerald-200" : "text-muted-foreground"
              )}
            >
              {f.enabled ? "Enabled" : "Disabled"}
            </button>
          </div>

          <div className="space-y-1 md:col-span-2">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Command pattern</label>
            <input
              value={f.pattern}
              onChange={(e) => setF((s) => ({ ...s, pattern: e.target.value }))}
              className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60 font-mono"
              placeholder="e.g. apt update"
            />
            <div className="text-[11px] text-muted-foreground">
              Tip: for <span className="font-mono">prefix</span>, start with the binary name (e.g. <span className="font-mono">systemctl </span>).
            </div>
          </div>

          <div className="space-y-1">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Scope: agent_id (optional)</label>
            <input
              value={f.agent_id}
              onChange={(e) => setF((s) => ({ ...s, agent_id: e.target.value }))}
              className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60 font-mono"
              placeholder="agent-123"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Scope: username (optional)</label>
            <input
              value={f.username}
              onChange={(e) => setF((s) => ({ ...s, username: e.target.value }))}
              className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60 font-mono"
              placeholder="root / ubuntu / admin"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Scope: target user (optional)</label>
            <input
              value={f.target_user}
              onChange={(e) => setF((s) => ({ ...s, target_user: e.target.value }))}
              className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60 font-mono"
              placeholder="root"
            />
          </div>

          <div className="space-y-1 md:col-span-2">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Notes (optional)</label>
            <input
              value={f.notes}
              onChange={(e) => setF((s) => ({ ...s, notes: e.target.value }))}
              className="w-full h-10 px-3 border border-border/60 bg-background/40 text-sm outline-none focus:border-primary/60"
              placeholder="Why this is safe / expected"
            />
          </div>
        </div>

        {err ? (
          <div className="border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">{err}</div>
        ) : null}

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={save}
            disabled={busy || !canSave}
            className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/40 px-4 text-[10px] font-mono uppercase tracking-widest hover:bg-background/60 disabled:opacity-60"
          >
            {busy ? "Saving…" : "Save"}
          </button>

          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-10 items-center justify-center border border-border/60 bg-background/20 px-4 text-[10px] font-mono uppercase tracking-widest text-muted-foreground hover:bg-background/40"
          >
            Cancel
          </button>
        </div>

        <div className="border-t border-border/60 pt-4 text-[11px] text-muted-foreground">
          Security note: allowlisting reduces detection sensitivity. Prefer scoping rules (agent/user) and keep patterns narrow.
        </div>
      </div>
    </Drawer>
  );
}
