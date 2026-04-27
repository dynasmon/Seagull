import { Button } from "@/shared/components/Button";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";
import { AssetFilters, SEVERITY_OPTIONS, SORT_OPTIONS } from "../filters";

type Props = {
  filters: AssetFilters;
  onChange: (next: Partial<AssetFilters>) => void;
  onReset?: () => void;
};

export function ExposureFiltersBar({ filters, onChange, onReset }: Props) {
  const hasFilters =
    filters.q ||
    filters.severity ||
    filters.has_attack_chain ||
    filters.has_critical_vuln ||
    filters.has_persistence_signal;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <TextInput
        placeholder="Search assets…"
        value={filters.q}
        onChange={(e) => onChange({ q: e.target.value })}
        className="h-8 w-48"
      />

      <SelectInput
        value={filters.severity}
        onChange={(e) => onChange({ severity: e.target.value as AssetFilters["severity"] })}
        className="h-8"
      >
        {SEVERITY_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </SelectInput>

      <SelectInput
        value={filters.sort}
        onChange={(e) => onChange({ sort: e.target.value as AssetFilters["sort"] })}
        className="h-8"
      >
        {SORT_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </SelectInput>

      <label className="flex cursor-pointer items-center gap-1.5 text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
        <input
          type="checkbox"
          checked={filters.has_attack_chain === true}
          onChange={(e) => onChange({ has_attack_chain: e.target.checked ? true : null })}
          className="h-3 w-3 accent-primary"
        />
        Attack chain
      </label>

      <label className="flex cursor-pointer items-center gap-1.5 text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
        <input
          type="checkbox"
          checked={filters.has_critical_vuln === true}
          onChange={(e) => onChange({ has_critical_vuln: e.target.checked ? true : null })}
          className="h-3 w-3 accent-primary"
        />
        Critical vuln
      </label>

      <label className="flex cursor-pointer items-center gap-1.5 text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
        <input
          type="checkbox"
          checked={filters.has_persistence_signal === true}
          onChange={(e) => onChange({ has_persistence_signal: e.target.checked ? true : null })}
          className="h-3 w-3 accent-primary"
        />
        Persistence
      </label>

      {hasFilters && onReset && (
        <Button variant="ghost" size="sm" onClick={onReset}>
          Reset
        </Button>
      )}
    </div>
  );
}
