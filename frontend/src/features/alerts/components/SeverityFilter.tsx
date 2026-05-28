import { SelectInput } from "@/shared/components/SelectInput";

export default function SeverityFilter(props: {
  value: string;
  onChange: (v: string) => void;
  className?: string;
}) {
  return (
    <SelectInput
      value={props.value}
      onChange={(e) => props.onChange(e.target.value)}
      className={props.className}
      title="Severity filter"
      aria-label="Severity filter"
    >
      <option value="all">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="unknown">Unknown</option>
    </SelectInput>
  );
}
