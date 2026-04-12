import { memo, useEffect, useMemo } from "react";

import DraftNumberInput from "@/shared/components/DraftNumberInput";
import { DataLookbackSelect, DebouncedSearchInput } from "@/shared/components/DataView";
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
  config?: EventsViewConfig;
  value?: EventsViewConfig;

  onChange?: (next: EventsViewConfig) => void;

  agents?: AgentOption[];

  // When set, agent selection is driven by the sidebar (global scope).
  lockAgentId?: string | null;
  lockEventType?: string | null;
  hideEventType?: boolean;

  busy?: boolean;
};

const DEFAULTS: { search: string; window_minutes: number; limit: number } = {
  search: "",
  window_minutes: 60,
  limit: 200
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

function EventsFiltersImpl(props: Props) {
  const cfg = useMemo(() => norm(props.config ?? props.value), [props.config, props.value]);

  const lockedAgentId = (props.lockAgentId ?? null) || null;
  const lockedEventType = (props.lockEventType ?? null) || null;
  const hideEventType = Boolean(props.hideEventType);
  const effectiveAgentId = lockedAgentId ? lockedAgentId : (cfg.agent_id ?? null);
  const effectiveEventType = lockedEventType ? lockedEventType : (cfg.event_type ?? null);

  const effectiveCfg = useMemo<EventsViewConfig>(() => {
    return norm({ ...cfg, agent_id: effectiveAgentId, event_type: effectiveEventType });
  }, [cfg, effectiveAgentId, effectiveEventType]);

  // Keep config consistent when the sidebar selection changes.
  useEffect(() => {
    if (!props.onChange) return;
    const a = JSON.stringify(cfg);
    const b = JSON.stringify(effectiveCfg);
    if (a !== b) props.onChange(effectiveCfg);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lockedAgentId, lockedEventType]);

  function patch(next: Partial<EventsViewConfig>) {
    const merged = norm({ ...effectiveCfg, ...next });
    if (lockedAgentId) merged.agent_id = lockedAgentId;
    if (lockedEventType) merged.event_type = lockedEventType;
    props.onChange?.(merged);
  }

  const agents = useMemo(() => props.agents ?? [], [props.agents]);
  const busy = Boolean(props.busy);

  const agentLabel = useMemo(() => {
    if (!effectiveCfg.agent_id) return "";
    const found = agents.find((a) => a.agent_id === effectiveCfg.agent_id);
    if (!found) return effectiveCfg.agent_id;
    return found.display_name ? `${found.display_name} (${found.agent_id})` : found.agent_id;
  }, [agents, effectiveCfg.agent_id]);

  return (
    <div className="space-y-3">
      {/* Agent scope */}
      <div>
        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Agent</div>

        {lockedAgentId ? (
          <>
            <input
              value={agentLabel || lockedAgentId}
              readOnly
              className={cx(
                "mt-1 w-full border border-border/60 bg-background/30 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
                "opacity-80"
              )}
            />
            <div className="mt-1 text-[11px] text-muted-foreground">
              Scope is set in the sidebar (Agent picker).
            </div>
          </>
        ) : (
          <select
            value={effectiveCfg.agent_id ?? ""}
            onChange={(e) => patch({ agent_id: e.target.value ? e.target.value : null })}
            disabled={busy}
            className={cx(
              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
              "focus:ring-2 focus:ring-primary/30",
              busy && "opacity-60 cursor-not-allowed"
            )}
          >
            <option value="">All agents</option>
            {agents.map((a) => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.display_name ? a.display_name : a.agent_id}
              </option>
            ))}
          </select>
        )}
      </div>

      {!hideEventType ? (
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Event type</div>
          {lockedEventType ? (
            <>
              <input
                value={lockedEventType}
                readOnly
                className={cx(
                  "mt-1 w-full border border-border/60 bg-background/30 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
                  "opacity-80"
                )}
              />
              <div className="mt-1 text-[11px] text-muted-foreground">Event type is locked for this module.</div>
            </>
          ) : (
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
              <option value="ddos_attack">ddos_attack</option>
              <option value="ssh_auth">ssh_auth</option>
              <option value="scan_probe">scan_probe</option>
              <option value="lateral_conn">lateral_conn</option>
              <option value="flow">flow</option>
            </select>
          )}
        </div>
      ) : null}

      {/* Search */}
      <div>
        <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Search</div>
        <DebouncedSearchInput
          value={effectiveCfg.search ?? ""}
          onChange={(value) => patch({ search: value })}
          disabled={busy}
          delayMs={350}
          placeholder="ip, user, rule, target, vector..."
          className={cx("mt-1 h-9 text-[11px]", busy && "opacity-60 cursor-not-allowed")}
        />
      </div>

      {/* Window + Limit */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
            Window (min)
          </div>
          <DataLookbackSelect
            value={Number(effectiveCfg.window_minutes ?? DEFAULTS.window_minutes)}
            onChange={(v) => patch({ window_minutes: v })}
            options={[
              { label: "15 min", minutes: 15 },
              { label: "30 min", minutes: 30 },
              { label: "1 hour", minutes: 60 },
              { label: "6 hours", minutes: 360 },
              { label: "24 hours", minutes: 1440 }
            ]}
            disabled={busy}
            className={cx(
              "mt-1 h-9 w-full text-[11px] font-mono",
              busy && "opacity-60 cursor-not-allowed"
            )}
          />
        </div>

        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">Limit</div>
          <DraftNumberInput
            value={Number(effectiveCfg.limit ?? DEFAULTS.limit)}
            min={10}
            max={500}
            fallback={DEFAULTS.limit}
            onCommit={(v) => patch({ limit: v })}
            disabled={busy}
            className={cx(
              "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-[11px] text-foreground outline-none font-mono",
              "focus:ring-2 focus:ring-primary/30",
              busy && "opacity-60 cursor-not-allowed"
            )}
            title="Max events to fetch"
          />
        </div>
      </div>
    </div>
  );
}

export default memo(EventsFiltersImpl);
