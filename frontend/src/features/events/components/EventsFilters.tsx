import { useEffect, useMemo } from "react";
import { cx } from "@/shared/lib/cx";

export type EventsViewConfig = {
  agent_id?: string | null;
  event_type?: string | null;
  search?: string | null;
  window_minutes?: number | null;
  limit?: number | null;
};

type AgentOption = {
  agent_id: string;
  display_name?: string | null;
};

type Props = {
  // Accept both names to stay compatible with older pages
  config?: EventsViewConfig;
  value?: EventsViewConfig;

  // Update callback
  onChange?: (next: EventsViewConfig) => void;

  // Agent list (optional)
  agents?: AgentOption[];

  // When set, agent selection is locked to this agent id (sidebar rule)
  lockAgentId?: string | null;

  // Disable inputs while loading
  busy?: boolean;
};

const DEFAULTS: Required<Pick<EventsViewConfig, "search" | "window_minutes" | "limit">> = {
  search: "",
  window_minutes: 60,
  limit: 500
};

function norm(cfg: EventsViewConfig | undefined | null): EventsViewConfig {
  const c = cfg ?? {};
  return {
    agent_id: (c.agent_id ?? null) || null,
    event_type: (c.event_type ?? null) || null,
    search: (c.search ?? DEFAULTS.search) ?? DEFAULTS.search,
    window_minutes: Number.isFinite(Number(c.window_minutes)) ? Number(c.window_minutes) : DEFAULTS.window_minutes,
    limit: Number.isFinite(Number(c.limit)) ? Number(c.limit) : DEFAULTS.limit
  };
}

export default function EventsFilters(props: Props) {
  const cfg = useMemo(() => norm(props.config ?? props.value), [props.config, props.value]);

  // Sidebar-selected agent always wins (lock)
  const effectiveAgentId = (props.lockAgentId ?? cfg.agent_id ?? null) || null;

  const effectiveCfg = useMemo<EventsViewConfig>(() => {
    const merged: EventsViewConfig = { ...cfg, agent_id: effectiveAgentId };
    return norm(merged);
  }, [cfg, effectiveAgentId]);

  // Auto-sync config once when lockAgentId changes (prevents mismatched state)
  useEffect(() => {
    if (!props.onChange) return;

    const a = JSON.stringify(cfg);
    const b = JSON.stringify(effectiveCfg);
    if (a !== b) props.onChange(effectiveCfg);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effectiveAgentId]);

  function patch(next: Partial<EventsViewConfig>) {
    const merged = norm({ ...effectiveCfg, ...next });

    // Enforce lock
    if (props.lockAgentId) merged.agent_id = props.lockAgentId;

    props.onChange?.(merged);
  }

  const agents = props.agents ?? [];
  const busy = Boolean(props.busy);

  return (
    <div className="space-y-3">
      {/* Agent */}
      <div>
        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent</div>
        <select
          value={effectiveCfg.agent_id ?? ""}
          onChange={(e) => patch({ agent_id: e.target.value ? e.target.value : null })}
          disabled={busy || Boolean(props.lockAgentId)}
          className={cx(
            "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
            "focus:ring-2 focus:ring-primary/30",
            (busy || Boolean(props.lockAgentId)) && "opacity-60 cursor-not-allowed"
          )}
        >
          <option value="">All agents</option>
          {agents.map((a) => (
            <option key={a.agent_id} value={a.agent_id}>
              {a.display_name ? a.display_name : a.agent_id}
            </option>
          ))}
        </select>

        {props.lockAgentId && <div className="mt-1 text-[11px] text-muted-foreground">Locked by sidebar selection</div>}
      </div>

      {/* Event type */}
      <div>
        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Event type</div>
        <select
          value={effectiveCfg.event_type ?? ""}
          onChange={(e) => patch({ event_type: e.target.value ? e.target.value : null })}
          disabled={busy}
          className={cx(
            "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
            "focus:ring-2 focus:ring-primary/30",
            busy && "opacity-60 cursor-not-allowed"
          )}
        >
          <option value="">All types</option>
          <option value="dos_attack">dos_attack</option>
          <option value="ssh_auth">ssh_auth</option>
          <option value="scan_probe">scan_probe</option>
          <option value="lateral_conn">lateral_conn</option>
          <option value="flow">flow</option>
        </select>
      </div>

      {/* Search */}
      <div>
        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Search</div>
        <input
          value={effectiveCfg.search ?? ""}
          onChange={(e) => patch({ search: e.target.value })}
          disabled={busy}
          placeholder="ip, user, rule, target, vector..."
          className={cx(
            "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
            "placeholder:text-muted-foreground/60 focus:ring-2 focus:ring-primary/30",
            busy && "opacity-60 cursor-not-allowed"
          )}
        />
      </div>

      {/* Window + Limit */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Window (min)</div>
          <input
            type="number"
            value={String(effectiveCfg.window_minutes ?? DEFAULTS.window_minutes)}
            onChange={(e) => patch({ window_minutes: Number(e.target.value) })}
            disabled={busy}
            className={cx(
              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
              "focus:ring-2 focus:ring-primary/30",
              busy && "opacity-60 cursor-not-allowed"
            )}
          />
        </div>

        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Limit</div>
          <input
            type="number"
            value={String(effectiveCfg.limit ?? DEFAULTS.limit)}
            onChange={(e) => patch({ limit: Number(e.target.value) })}
            disabled={busy}
            className={cx(
              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
              "focus:ring-2 focus:ring-primary/30",
              busy && "opacity-60 cursor-not-allowed"
            )}
          />
        </div>
      </div>
    </div>
  );
}
