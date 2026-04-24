import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type SeverityVariant = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const map: Record<SeverityVariant, string> = {
  critical: "border-severity-critical/45 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/45 bg-severity-high/10 text-severity-high",
  medium: "border-severity-medium/45 bg-severity-medium/10 text-severity-medium",
  low: "border-severity-low/45 bg-severity-low/10 text-severity-low",
  info: "border-info/45 bg-info/10 text-info",
  neutral: "border-border/70 bg-muted/40 text-muted-foreground",
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
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em]",
        map[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}
