import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";
import type { Agent, EventsViewConfig } from "../types";

function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
      {children}
    </div>
  );
}

function selectClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-sm text-foreground outline-none",
    "focus:ring-2 focus:ring-primary/30",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

function inputClassName(disabled?: boolean) {
  return cx(
    "mt-1 w-full border border-border/60 bg-background/40 px-3 py-2 text-sm text-foreground outline-none",
    "placeholder:text-muted-foreground/60",
    "focus:ring-2 focus:ring-primary/30",
    disabled && "opacity-60 cursor-not-allowed"
  );
}

function Switch({
  checked,
  onChange,
  disabled,
  label
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label: string;
}) {
  return (
    <div className={cx("flex items-center justify-between gap-3", disabled && "opacity-60")}>
      <span className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
        {label}
      </span>

      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={cx(
          "relative inline-flex h-6 w-11 items-center rounded-full border border-border/60",
          "bg-background/40 transition-colors",
          "focus:outline-none focus:ring-2 focus:ring-primary/30",
          "disabled:cursor-not-allowed",
          checked && "bg-primary/15"
        )}
      >
        <span
          className={cx(
            "inline-block h-5 w-5 transform rounded-full bg-foreground/80",
            "transition-transform",
            checked ? "translate-x-5" : "translate-x-1"
          )}
        />
      </button>
    </div>
  );
}

export default function EventsFilters({
  agents,
  eventTypes,
  config,
  isLoading,
  onChange,
  onRefresh
}: {
  agents: Agent[];
  eventTypes: string[];
  config: EventsViewConfig;
  isLoading: boolean;
  onChange: (next: EventsViewConfig) => void;
  onRefresh: () => void;
}) {
  const windows = [
    { label: "15m", value: 15 },
    { label: "60m", value: 60 },
    { label: "6h", value: 360 },
    { label: "24h", value: 1440 }
  ];

  const refreshes = [
    { label: "2s", value: 2000 },
    { label: "5s", value: 5000 },
    { label: "10s", value: 10000 },
    { label: "30s", value: 30000 }
  ];

  const limits = [200, 500, 1000];

  return (
    <div className="grid gap-4 lg:grid-cols-12">
      {/* LEFT: main filters */}
      <div className="lg:col-span-9 space-y-4">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div>
            <FieldLabel>Agent</FieldLabel>
            <select
              className={selectClassName(isLoading)}
              disabled={isLoading}
              value={config.agent_id}
              onChange={(e) => onChange({ ...config, agent_id: e.target.value })}
            >
              <option value="">All agents</option>
              {agents.map((a) => (
                <option key={a.agent_id} value={a.agent_id}>
                  {a.agent_id}
                </option>
              ))}
            </select>
          </div>

          <div>
            <FieldLabel>Event type</FieldLabel>
            <select
              className={selectClassName(isLoading)}
              disabled={isLoading}
              value={config.event_type}
              onChange={(e) => onChange({ ...config, event_type: e.target.value })}
            >
              <option value="">All types</option>
              {eventTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>

          <div>
            <FieldLabel>Time window</FieldLabel>
            <select
              className={selectClassName(isLoading)}
              disabled={isLoading}
              value={String(config.window_minutes)}
              onChange={(e) =>
                onChange({ ...config, window_minutes: Number(e.target.value) })
              }
            >
              {windows.map((w) => (
                <option key={w.value} value={String(w.value)}>
                  {w.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <FieldLabel>Limit</FieldLabel>
            <select
              className={selectClassName(isLoading)}
              disabled={isLoading}
              value={String(config.limit)}
              onChange={(e) => onChange({ ...config, limit: Number(e.target.value) })}
            >
              {limits.map((l) => (
                <option key={l} value={String(l)}>
                  {l}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <FieldLabel>Search</FieldLabel>
          <input
            className={inputClassName(false)}
            value={config.search}
            onChange={(e) => onChange({ ...config, search: e.target.value })}
            placeholder="agent_id / src_ip / dst_ip / port / proto / extra"
          />
        </div>

        <div className="text-[11px] text-muted-foreground">
          Filters <span className="font-mono">agent_id</span> and{" "}
          <span className="font-mono">event_type</span> are applied server-side.
          Time window and search are applied client-side on the last {config.limit} events.
        </div>
      </div>

      {/* RIGHT: actions + options (clean, aligned) */}
      <div className="lg:col-span-3 space-y-3">
        <div className="border border-border/60 bg-background/40 p-3 space-y-3">
          <div className="flex items-center justify-between">
            <FieldLabel>Options</FieldLabel>
            <button
              type="button"
              onClick={onRefresh}
              disabled={isLoading}
              className={cx(
                "border border-border/60 bg-background/40 px-3 py-2 text-[10px] font-mono font-bold uppercase tracking-widest",
                "hover:bg-primary/5",
                isLoading && "opacity-60 cursor-not-allowed"
              )}
            >
              Refresh
            </button>
          </div>

          <Switch
            checked={config.auto_refresh}
            onChange={(v) => onChange({ ...config, auto_refresh: v })}
            disabled={false}
            label="Auto refresh"
          />

          <div className="grid grid-cols-2 items-center gap-3">
            <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">
              Interval
            </div>
            <select
              className={selectClassName(!config.auto_refresh)}
              disabled={!config.auto_refresh}
              value={String(config.refresh_ms)}
              onChange={(e) =>
                onChange({ ...config, refresh_ms: Number(e.target.value) })
              }
            >
              {refreshes.map((r) => (
                <option key={r.value} value={String(r.value)}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>

          <div className="border-t border-border/60 pt-3 space-y-3">
            <Switch
              checked={config.compact_rows}
              onChange={(v) => onChange({ ...config, compact_rows: v })}
              disabled={false}
              label="Compact rows"
            />
            <Switch
              checked={config.show_extra}
              onChange={(v) => onChange({ ...config, show_extra: v })}
              disabled={false}
              label="Show extra"
            />
          </div>
        </div>

        {isLoading && (
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground opacity-80">
            loading…
          </div>
        )}
      </div>
    </div>
  );
}
