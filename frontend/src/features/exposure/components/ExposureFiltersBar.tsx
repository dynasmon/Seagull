import AgentFilter from "@/features/agents/components/AgentFilter";
import { Button } from "@/shared/components/Button";
import { CheckboxField } from "@/shared/components/CheckboxField";
import { DataFilterGroup, DataViewFilterBar } from "@/shared/components/DataView";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";

import {
  ASSET_STATUS_OPTIONS,
  AssetFilters,
  SEVERITY_OPTIONS,
  SORT_OPTIONS,
} from "../filters";

type Option = {
  value: string;
  label: string;
};

type Props = {
  filters: AssetFilters;
  reasonCodeOptions: Option[];
  onChange: (next: Partial<AssetFilters>) => void;
  onApply: () => void;
  onReset?: () => void;
  applying?: boolean;
};

export function ExposureFiltersBar({
  filters,
  reasonCodeOptions,
  onChange,
  onApply,
  onReset,
  applying,
}: Props) {
  const hasFilters = Boolean(
    filters.q ||
      filters.severity ||
      filters.min_score !== null ||
      filters.agent_id ||
      filters.reason_code ||
      filters.status ||
      filters.has_attack_chain ||
      filters.has_critical_vuln ||
      filters.has_persistence_signal,
  );

  return (
    <div className="space-y-3">
      <DataViewFilterBar>
        <DataFilterGroup label="Search">
          <TextInput
            placeholder="Asset name, key, hostname"
            value={filters.q}
            onChange={(event) => onChange({ q: event.target.value })}
            className="w-full font-mono text-xs"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Severity">
          <SelectInput
            value={filters.severity}
            onChange={(event) => onChange({ severity: event.target.value as AssetFilters["severity"] })}
            className="w-full font-mono text-xs"
          >
            {SEVERITY_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Min Score">
          <TextInput
            type="number"
            min={0}
            max={100}
            step={1}
            value={filters.min_score ?? ""}
            onChange={(event) =>
              onChange({
                min_score: event.target.value === "" ? null : Number.isFinite(Number(event.target.value)) ? Number(event.target.value) : null,
              })
            }
            className="w-full font-mono text-xs"
          />
        </DataFilterGroup>

        <DataFilterGroup label="Agent">
          <AgentFilter value={filters.agent_id} onChange={(agentId) => onChange({ agent_id: agentId })} fullWidth />
        </DataFilterGroup>

        <DataFilterGroup label="Reason Code">
          <SelectInput
            value={filters.reason_code}
            onChange={(event) => onChange({ reason_code: event.target.value })}
            className="w-full font-mono text-xs"
          >
            <option value="">All reason codes</option>
            {reasonCodeOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Status">
          <SelectInput
            value={filters.status}
            onChange={(event) => onChange({ status: event.target.value as AssetFilters["status"] })}
            className="w-full font-mono text-xs"
          >
            {ASSET_STATUS_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Sort">
          <SelectInput
            value={filters.sort}
            onChange={(event) => onChange({ sort: event.target.value as AssetFilters["sort"] })}
            className="w-full font-mono text-xs"
          >
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </SelectInput>
        </DataFilterGroup>

        <DataFilterGroup label="Signals">
          <div className="grid gap-2">
            <CheckboxField
              label="Has attack chain"
              checked={filters.has_attack_chain === true}
              onChange={(event) => onChange({ has_attack_chain: event.target.checked ? true : null })}
            />
            <CheckboxField
              label="Critical vulnerability"
              checked={filters.has_critical_vuln === true}
              onChange={(event) => onChange({ has_critical_vuln: event.target.checked ? true : null })}
            />
            <CheckboxField
              label="Persistence signal"
              checked={filters.has_persistence_signal === true}
              onChange={(event) => onChange({ has_persistence_signal: event.target.checked ? true : null })}
            />
          </div>
        </DataFilterGroup>
      </DataViewFilterBar>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-[11px] font-mono text-muted-foreground">
          {hasFilters ? "Custom asset risk filters applied or staged" : "Default asset risk view"}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {onReset ? (
            <Button variant="ghost" size="sm" onClick={onReset}>
              Reset
            </Button>
          ) : null}
          <Button variant="secondary" size="sm" onClick={onApply} disabled={applying}>
            {applying ? "Applying…" : "Apply"}
          </Button>
        </div>
      </div>
    </div>
  );
}
