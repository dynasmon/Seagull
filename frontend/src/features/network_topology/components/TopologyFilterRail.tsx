import { useCallback, useState } from "react";

import { Button } from "@/shared/components/Button";
import { CheckboxField } from "@/shared/components/CheckboxField";
import DraftNumberInput from "@/shared/components/DraftNumberInput";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";
import { ToggleSwitch } from "@/shared/components/ToggleSwitch";
import { cx } from "@/shared/lib/cx";

import {
  DEFAULT_TOPOLOGY_FILTERS,
  TOPOLOGY_EDGE_TYPE_OPTIONS,
  TOPOLOGY_IP_SCOPE_OPTIONS,
  TOPOLOGY_NODE_TYPE_OPTIONS,
  TOPOLOGY_SEVERITY_OPTIONS,
  TOPOLOGY_TIME_WINDOWS,
} from "../lib/filters";
import { nodeVisualByType } from "../lib/visuals";
import type { TopologyFacets, TopologyFilters, TopologyGroup, TopologyIpScope, TopologySeverity, TopologyViewMode } from "../types";

const SEVERITY_DOT: Record<string, string> = {
  critical:      "#F87171",
  high:          "#F97316",
  medium:        "#FBBF24",
  low:           "#4ADE80",
  informational: "#60A5FA",
  unknown:       "#9CA3AF",
};

type AgentOption = { value: string; label: string };

type SectionProps = {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
};

function FilterSection({ title, defaultOpen = true, children }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border-b border-border/30">
      <button
        type="button"
        className="flex w-full items-center justify-between px-3 py-2 text-left"
        onClick={() => setOpen((prev) => !prev)}
      >
        <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
          {title}
        </span>
        <span
          className={cx(
            "text-[10px] text-muted-foreground/60 transition-transform",
            open ? "rotate-90" : "rotate-0",
          )}
        >
          ▶
        </span>
      </button>
      {open && <div className="px-3 pb-3">{children}</div>}
    </div>
  );
}

function toggle<T extends string>(arr: T[], value: T): T[] {
  return arr.includes(value) ? arr.filter((v) => v !== value) : [...arr, value];
}

type Props = {
  filters: TopologyFilters;
  agentOptions: AgentOption[];
  groups: TopologyGroup[];
  dirty: boolean;
  applying: boolean;
  facets?: TopologyFacets;
  onChange: (patch: Partial<TopologyFilters>) => void;
  onViewModeChange: (mode: TopologyViewMode) => void;
  onApply: () => void;
  onReset: () => void;
};

export function TopologyFilterRail({
  filters,
  agentOptions,
  groups,
  dirty,
  applying,
  facets,
  onChange,
  onViewModeChange,
  onApply,
  onReset,
}: Props) {
  const handleViewMode = useCallback(
    (mode: TopologyViewMode) => onViewModeChange(mode),
    [onViewModeChange],
  );

  const handleSeverity = useCallback(
    (sv: TopologySeverity) => onChange({ severities: toggle(filters.severities, sv) }),
    [filters.severities, onChange],
  );

  const handleNodeType = useCallback(
    (nt: string) => onChange({ node_types: toggle(filters.node_types, nt) }),
    [filters.node_types, onChange],
  );

  const handleEdgeType = useCallback(
    (et: string) => onChange({ edge_types: toggle(filters.edge_types, et) }),
    [filters.edge_types, onChange],
  );

  const handleIpScope = useCallback(
    (scope: TopologyIpScope) => onChange({ ip_scopes: toggle(filters.ip_scopes, scope) }),
    [filters.ip_scopes, onChange],
  );

  const agentSelectOptions = [
    { value: "", label: "All agents" },
    ...agentOptions,
  ];

  const timeWindowOptions = TOPOLOGY_TIME_WINDOWS.map((tw) => ({
    value: String(tw.value),
    label: tw.label,
  }));
  const groupOptions = [...groups]
    .sort((a, b) => {
      const alertDelta = b.alert_count - a.alert_count;
      if (alertDelta !== 0) return alertDelta;
      const riskDelta = b.risk_score - a.risk_score;
      if (riskDelta !== 0) return riskDelta;
      const countDelta = b.node_count - a.node_count;
      if (countDelta !== 0) return countDelta;
      return a.label.localeCompare(b.label);
    })
    .slice(0, 12);
  const selectedGroupVisible = groupOptions.some((group) => group.group_key === filters.group_key);
  const selectedGroup = !selectedGroupVisible
    ? groups.find((group) => group.group_key === filters.group_key) ?? null
    : null;

  return (
    <div className="flex h-full w-[216px] shrink-0 flex-col overflow-y-auto border-r border-white/5 bg-[#09111d]/92">
      <div className="border-b border-border/30 px-3 py-2.5">
        <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground/65">
          Show
        </div>
        <div className="mt-2 flex rounded-md border border-white/10 bg-black/20 p-0.5">
          {(["location", "connection"] as TopologyViewMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              className={cx(
                "flex-1 rounded-[4px] px-2 py-1.5 text-[11px] font-medium transition-all",
                filters.view_mode === mode
                  ? "bg-primary/90 text-primary-foreground shadow-[0_0_16px_rgba(96,165,250,0.15)]"
                  : "text-muted-foreground hover:bg-white/5",
              )}
              onClick={() => handleViewMode(mode)}
            >
              {mode === "location" ? "Location" : "Connection"}
            </button>
          ))}
        </div>
        {facets ? (
          <div className="mt-2 text-[10px] text-muted-foreground/55">
            {facets.group_count} groups · {facets.node_types.subnet ?? 0} subnet{(facets.node_types.subnet ?? 0) === 1 ? "" : "s"}
          </div>
        ) : null}
      </div>

      <div className="border-b border-border/30 px-3 py-2.5">
        <TextInput
          placeholder="Search nodes, IPs, ports…"
          value={filters.q}
          onChange={(e) => onChange({ q: e.target.value })}
          className="h-7 text-[12px]"
        />
      </div>

      <FilterSection title="Severity">
        <div className="space-y-1.5">
          {TOPOLOGY_SEVERITY_OPTIONS.map(({ value, label }) => {
            const count = facets?.severities[value];
            return (
              <CheckboxField
                key={value}
                label={
                  <span className="flex items-center gap-1.5">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ background: SEVERITY_DOT[value] ?? "#9CA3AF" }}
                    />
                    <span className="text-[12px]">{label}</span>
                    {count != null && (
                      <span className="ml-auto text-[10px] text-muted-foreground/60">{count}</span>
                    )}
                  </span>
                }
                checked={filters.severities.includes(value as TopologySeverity)}
                onChange={() => handleSeverity(value as TopologySeverity)}
              />
            );
          })}
        </div>
      </FilterSection>

      <FilterSection title="Type" defaultOpen={false}>
        <div className="space-y-1.5">
          {TOPOLOGY_NODE_TYPE_OPTIONS.map(({ value, label }) => {
            const visual = nodeVisualByType(value);
            const count = facets?.node_types[value];
            return (
              <CheckboxField
                key={value}
                label={
                  <span className="flex items-center gap-1.5">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ background: visual.stroke }}
                    />
                    <span className="text-[12px]">{label}</span>
                    {count != null && (
                      <span className="ml-auto text-[10px] text-muted-foreground/60">{count}</span>
                    )}
                  </span>
                }
                checked={filters.node_types.includes(value)}
                onChange={() => handleNodeType(value)}
              />
            );
          })}
        </div>
      </FilterSection>

      <FilterSection title="Location / Group" defaultOpen={false}>
        <div className="space-y-2">
          <SelectInput
            value={filters.group_key}
            onChange={(e) => onChange({ group_key: e.target.value })}
            className="h-7 text-[12px]"
          >
            <option value="">All locations</option>
            {selectedGroup && (
              <option value={selectedGroup.group_key}>{selectedGroup.label}</option>
            )}
            {groupOptions.map((group) => (
              <option key={group.group_key} value={group.group_key}>
                {group.label} ({group.node_count})
              </option>
            ))}
          </SelectInput>
          {groups.length > groupOptions.length && (
            <div className="text-[10px] text-muted-foreground/50">
              Showing {groupOptions.length} priority groups of {groups.length}
            </div>
          )}
        </div>
      </FilterSection>

      <FilterSection title="Status" defaultOpen={false}>
        <div className="space-y-2">
          <ToggleSwitch
            label={facets ? `Include stale nodes (${facets.stale_count})` : "Include stale nodes"}
            checked={filters.include_stale}
            onChange={(e) => onChange({ include_stale: e.target.checked })}
          />
          <ToggleSwitch
            label={facets ? `Has alerts (${facets.has_alerts_count})` : "Has alerts"}
            checked={filters.has_alerts}
            onChange={(e) => onChange({ has_alerts: e.target.checked })}
          />
          <ToggleSwitch
            label={facets ? `Has exposure findings (${facets.has_exposure_count})` : "Has exposure findings"}
            checked={filters.has_exposure}
            onChange={(e) => onChange({ has_exposure: e.target.checked })}
          />
        </div>
      </FilterSection>

      <FilterSection title="IP Scope" defaultOpen={false}>
        <div className="space-y-1.5">
          {TOPOLOGY_IP_SCOPE_OPTIONS.map(({ value, label }) => {
            const count = facets?.ip_scopes[value];
            return (
              <CheckboxField
                key={value}
                label={
                  <span className="flex items-center gap-1.5">
                    <span className="text-[12px]">{label}</span>
                    {count != null && (
                      <span className="ml-auto text-[10px] text-muted-foreground/60">{count}</span>
                    )}
                  </span>
                }
                checked={filters.ip_scopes.includes(value as TopologyIpScope)}
                onChange={() => handleIpScope(value as TopologyIpScope)}
              />
            );
          })}
        </div>
      </FilterSection>

      <FilterSection title="Edge Type" defaultOpen={false}>
        <div className="space-y-1.5">
          {TOPOLOGY_EDGE_TYPE_OPTIONS.map(({ value, label }) => {
            const count = facets?.edge_types[value];
            return (
              <CheckboxField
                key={value}
                label={
                  <span className="flex items-center gap-1.5">
                    <span className="text-[12px]">{label}</span>
                    {count != null && (
                      <span className="ml-auto text-[10px] text-muted-foreground/60">{count}</span>
                    )}
                  </span>
                }
                checked={filters.edge_types.includes(value)}
                onChange={() => handleEdgeType(value)}
              />
            );
          })}
        </div>
      </FilterSection>

      <FilterSection title="Agent" defaultOpen={false}>
        <SelectInput
          value={filters.agent_id}
          onChange={(e) => onChange({ agent_id: e.target.value })}
          className="h-7 text-[12px]"
        >
          {agentSelectOptions.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </SelectInput>
      </FilterSection>

      <FilterSection title="Time Window" defaultOpen={false}>
        <SelectInput
          value={String(filters.window_minutes)}
          onChange={(e) =>
            onChange({ window_minutes: Number(e.target.value) as TopologyFilters["window_minutes"] })
          }
          className="h-7 text-[12px]"
        >
          {timeWindowOptions.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </SelectInput>
      </FilterSection>

      <FilterSection title="Confidence" defaultOpen={false}>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-muted-foreground">Min:</span>
          <DraftNumberInput
            value={filters.min_confidence}
            onCommit={(v) => onChange({ min_confidence: v })}
            min={1}
            max={99}
            fallback={DEFAULT_TOPOLOGY_FILTERS.min_confidence}
            className="h-7 w-16 rounded-[4px] border border-border/50 bg-background/40 px-2 text-[12px]"
          />
          <span className="text-[11px] text-muted-foreground">%</span>
        </div>
      </FilterSection>

      <div className="mt-auto flex gap-2 border-t border-border/30 px-3 py-3">
        <Button
          variant="ghost"
          size="sm"
          className="flex-1 text-[12px]"
          onClick={onReset}
          disabled={applying}
        >
          Reset
        </Button>
        <Button
          variant="primary"
          size="sm"
          className="flex-1 text-[12px]"
          onClick={onApply}
          disabled={!dirty || applying}
        >
          {applying ? "Applying…" : "Apply"}
        </Button>
      </div>
    </div>
  );
}
