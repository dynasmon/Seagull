import { memo, useEffect, useMemo } from "react";

import AgentFilter from "@/features/agents/components/AgentFilter";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import { DataLookbackSelect, DebouncedSearchInput } from "@/shared/components/DataView";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";
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
  lockAgentId?: string | null;
  lockEventType?: string | null;
  hideEventType?: boolean;
  busy?: boolean;
};

const DEFAULTS: { search: string; window_minutes: number; limit: number } = {
  search: "",
  window_minutes: 60,
  limit: 200,
};

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{children}</div>
  );
}

function norm(cfg: EventsViewConfig | undefined | null): EventsViewConfig {
  const c = cfg ?? {};
  return {
    agent_id: (c.agent_id ?? null) || null,
    event_type: (c.event_type ?? null) || null,
    search: (c.search ?? DEFAULTS.search) ?? DEFAULTS.search,
    window_minutes: Number.isFinite(Number(c.window_minutes)) ? Number(c.window_minutes) : DEFAULTS.window_minutes,
    limit: Number.isFinite(Number(c.limit)) ? Number(c.limit) : DEFAULTS.limit,
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
      <div>
        <FieldLabel>Agent</FieldLabel>
        {lockedAgentId ? (
          <>
            <TextInput
              value={agentLabel || lockedAgentId}
              readOnly
              className={cx("mt-1 font-mono text-[11.5px] opacity-80")}
            />
            <div className="mt-1 text-[11px] text-muted-foreground">Scope is pinned to the agent selected in Fleet.</div>
          </>
        ) : (
          <AgentFilter
            value={effectiveCfg.agent_id ?? ""}
            onChange={(agentId) => patch({ agent_id: agentId || null })}
            isDisabled={busy}
            fullWidth
            className="mt-1"
          />
        )}
      </div>

      {!hideEventType ? (
        <div>
          <FieldLabel>Event type</FieldLabel>
          {lockedEventType ? (
            <>
              <TextInput
                value={lockedEventType}
                readOnly
                className="mt-1 font-mono text-[11.5px] opacity-80"
              />
              <div className="mt-1 text-[11px] text-muted-foreground">Event type is locked for this module.</div>
            </>
          ) : (
            <SelectInput
              value={effectiveCfg.event_type ?? ""}
              onChange={(e) => patch({ event_type: e.target.value ? e.target.value : null })}
              disabled={busy}
              className={cx("mt-1 font-mono text-[11.5px]", busy && "cursor-not-allowed opacity-60")}
            >
              <option value="">All types</option>
              <option value="dos_attack">dos_attack</option>
              <option value="ddos_attack">ddos_attack</option>
              <option value="ssh_auth">ssh_auth</option>
              <option value="scan_probe">scan_probe</option>
              <option value="lateral_conn">lateral_conn</option>
              <option value="flow">flow</option>
            </SelectInput>
          )}
        </div>
      ) : null}

      <div>
        <FieldLabel>Search</FieldLabel>
        <DebouncedSearchInput
          value={effectiveCfg.search ?? ""}
          onChange={(value) => patch({ search: value })}
          disabled={busy}
          delayMs={350}
          placeholder="ip, user, rule, target, vector..."
          className={cx("mt-1 h-9 text-[11.5px]", busy && "cursor-not-allowed opacity-60")}
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <FieldLabel>Window (min)</FieldLabel>
          <DataLookbackSelect
            value={Number(effectiveCfg.window_minutes ?? DEFAULTS.window_minutes)}
            onChange={(v) => patch({ window_minutes: v })}
            options={[
              { label: "15 min", minutes: 15 },
              { label: "30 min", minutes: 30 },
              { label: "1 hour", minutes: 60 },
              { label: "6 hours", minutes: 360 },
              { label: "24 hours", minutes: 1440 },
            ]}
            disabled={busy}
            className={cx("mt-1 h-9 w-full font-mono text-[11.5px]", busy && "cursor-not-allowed opacity-60")}
          />
        </div>

        <div>
          <FieldLabel>Limit</FieldLabel>
          <DraftNumberInput
            value={Number(effectiveCfg.limit ?? DEFAULTS.limit)}
            min={10}
            max={500}
            fallback={DEFAULTS.limit}
            onCommit={(v) => patch({ limit: v })}
            disabled={busy}
            className={cx("mt-1 font-mono text-[11.5px]", busy && "cursor-not-allowed opacity-60")}
            title="Max events to fetch"
          />
        </div>
      </div>
    </div>
  );
}

export default memo(EventsFiltersImpl);
