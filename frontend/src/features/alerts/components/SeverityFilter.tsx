import { cx } from "@/shared/lib/cx";

export default function SeverityFilter(props: {
  value: string;
  onChange: (v: string) => void;
  className?: string;
}) {
  return (
    <select
      value={props.value}
      onChange={(e) => props.onChange(e.target.value)}
      className={cx(
        "h-9 rounded-md border border-border/60 bg-background/40 px-3 text-sm outline-none focus:ring-1 focus:ring-primary/40",
        props.className
      )}
    >
      <option value="all">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="unknown">Unknown</option>
    </select>
  );
}
