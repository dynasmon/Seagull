import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type BadgeVariant = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const map: Record<BadgeVariant, string> = {
  critical: "border-severity-critical/45 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/45 bg-severity-high/10 text-severity-high",
  medium: "border-severity-medium/45 bg-severity-medium/10 text-severity-medium",
  low: "border-severity-low/45 bg-severity-low/10 text-severity-low",
  info: "border-info/45 bg-info/10 text-info",
  neutral: "border-border/70 bg-muted/40 text-muted-foreground",
};

export function Badge({
  children,
  variant = "neutral",
  className,
}: {
  children: ReactNode;
  variant?: BadgeVariant;
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
