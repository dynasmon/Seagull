import { cx } from "@/shared/lib/cx";

function fmtRisk(n: number | null | undefined): string {
  const v = Number(n || 0);
  if (!Number.isFinite(v)) return "0.0";
  return v.toFixed(1);
}

export function RiskScorePill({
  score,
  className,
}: {
  score: number | null | undefined;
  className?: string;
}) {
  const value = Number(score || 0);
  const tone =
    value >= 80
      ? "border-severity-critical/50 bg-severity-critical/10 text-severity-critical"
      : value >= 65
        ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
        : value >= 45
          ? "border-severity-medium/50 bg-severity-medium/10 text-severity-medium"
          : value > 0
            ? "border-severity-low/50 bg-severity-low/10 text-severity-low"
            : "border-border bg-surface-2 text-foreground";

  return (
    <span
      className={cx(
        "inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11.5px] font-semibold",
        tone,
        className,
      )}
      title={`Risk score ${fmtRisk(score)}`}
    >
      {fmtRisk(score)}
    </span>
  );
}
