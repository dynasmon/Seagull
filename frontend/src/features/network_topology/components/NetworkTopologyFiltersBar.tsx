import { Button } from "@/shared/components/Button";
import { DataFilterGroup, DataViewFilterBar } from "@/shared/components/DataView";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";

import {
  DEFAULT_TOPOLOGY_FILTERS,
  TOPOLOGY_EDGE_TYPE_OPTIONS,
  TOPOLOGY_IP_SCOPE_OPTIONS,
  TOPOLOGY_NODE_TYPE_OPTIONS,
  TOPOLOGY_SEVERITY_OPTIONS,
  TOPOLOGY_TIME_WINDOWS,
  hasActiveTopologyFilters,
} from "../lib/filters";
import type { TopologyFilters } from "../types";

type Option = {
  value: string;
  label: string;
};

export function NetworkTopologyFiltersBar({
  filters,
  agentOptions,
  onChange,
  onApply,
  onReset,
  dirty,
  applying,
}: {
  filters: TopologyFilters;
  agentOptions: Option[];
  onChange: (patch: Partial<TopologyFilters>) => void;
  onApply: () => void;
  onReset: () => void;
  dirty?: boolean;
  applying?: boolean;
}) {
  const active = hasActiveTopologyFilters(filters);

  return (
    <div className="space-y-3">
      <DataViewFilterBar className="xl:grid-cols-5">
        <DataFilterGroup label="Search" className="xl:col-span-2">
          <TextInput
            type="search"
            value={filters.q}
            placeholder="IP, hostname, service"
            onChange={(event) => onChange({ q: event.target.value })}
            className="font-mono text-xs"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Agent">
          <SelectInput
            value={filters.agent_id}
            onChange={(event) => onChange({ agent_id: event.target.value })}
            className="font-mono text-xs"
          >
            <option value="">All agents</option>
            {agentOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Time Window">
          <SelectInput
            value={String(filters.window_minutes)}
            onChange={(event) => onChange({ window_minutes: Number(event.target.value) as TopologyFilters["window_minutes"] })}
            className="font-mono text-xs"
          >
            {TOPOLOGY_TIME_WINDOWS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Min Confidence">
          <TextInput
            type="number"
            min={1}
            max={99}
            step={1}
            value={filters.min_confidence}
            onChange={(event) => {
              const next = Number(event.target.value);
              onChange({ min_confidence: Number.isFinite(next) ? Math.min(99, Math.max(1, next)) : DEFAULT_TOPOLOGY_FILTERS.min_confidence });
            }}
            className="font-mono text-xs"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Node Type">
          <SelectInput
            value={filters.node_type}
            onChange={(event) => onChange({ node_type: event.target.value })}
            className="font-mono text-xs"
          >
            {TOPOLOGY_NODE_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Edge Type">
          <SelectInput
            value={filters.edge_type}
            onChange={(event) => onChange({ edge_type: event.target.value })}
            className="font-mono text-xs"
          >
            {TOPOLOGY_EDGE_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="IP Scope">
          <SelectInput
            value={filters.ip_scope}
            onChange={(event) => onChange({ ip_scope: event.target.value })}
            className="font-mono text-xs"
          >
            {TOPOLOGY_IP_SCOPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Severity">
          <SelectInput
            value={filters.severity}
            onChange={(event) => onChange({ severity: event.target.value })}
            className="font-mono text-xs"
          >
            {TOPOLOGY_SEVERITY_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>
      </DataViewFilterBar>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-[11px] font-mono text-muted-foreground">
          {dirty ? "Filter changes staged" : active ? "Filtered topology view" : "Default topology view"}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="ghost" size="sm" onClick={onReset}>
            Reset
          </Button>
          <Button variant="secondary" size="sm" onClick={onApply} disabled={!dirty || applying}>
            {applying ? "Applying..." : "Apply"}
          </Button>
        </div>
      </div>
    </div>
  );
}
