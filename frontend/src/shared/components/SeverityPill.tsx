import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type SeverityVariant = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const map: Record<SeverityVariant, string> = {
  critical: "border-severity-critical/40 bg-severity-critical/15 text-severity-critical",
  high: "border-severity-high/40 bg-severity-high/15 text-severity-high",
  medium: "border-severity-medium/40 bg-severity-medium/15 text-severity-medium",
  low: "border-severity-low/40 bg-severity-low/15 text-severity-low",
  info: "border-info/40 bg-info/15 text-info",
  neutral: "border-border bg-muted text-muted-foreground",
};

export function SeverityPill({
  variant = "neutral",
  children,
  className,
}: {
  variant?: SeverityVariant;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cx(
        "inline-flex items-center whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em]",
        map[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}
