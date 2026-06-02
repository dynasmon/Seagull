import { FilterBar, FilterButtonSelect } from "@/shared/components/FilterBar";

const SEVERITY_OPTIONS = [
  { value: "all", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "unknown", label: "Unknown" },
];

export default function SeverityFilter(props: {
  value: string;
  onChange: (v: string) => void;
  className?: string;
}) {
  return (
    <FilterBar>
      <FilterButtonSelect
        label="Severity"
        value={props.value}
        options={SEVERITY_OPTIONS}
        onChange={props.onChange}
      />
    </FilterBar>
  );
}
