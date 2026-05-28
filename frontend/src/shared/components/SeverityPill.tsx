import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type SeverityVariant = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const surface: Record<SeverityVariant, string> = {
  critical: "border-severity-critical/40 bg-severity-critical/12 text-severity-critical",
  high: "border-severity-high/40 bg-severity-high/12 text-severity-high",
  medium: "border-severity-medium/40 bg-severity-medium/12 text-severity-medium",
  low: "border-severity-low/40 bg-severity-low/12 text-severity-low",
  info: "border-info/40 bg-info/12 text-info",
  neutral: "border-border bg-muted text-muted-foreground",
};

const dotColor: Record<SeverityVariant, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-info",
  neutral: "bg-muted-foreground/60",
};

export function SeverityPill({
  variant = "neutral",
  children,
  className,
  withDot = false,
  size = "default",
}: {
  variant?: SeverityVariant;
  children: ReactNode;
  className?: string;
  withDot?: boolean;
  size?: "default" | "sm";
}) {
  const sizeClass = size === "sm" ? "px-1.5 py-[1px] text-[9.5px]" : "px-1.5 py-0.5 text-[10px]";
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-sm border font-semibold uppercase tracking-[0.05em]",
        sizeClass,
        surface[variant],
        className,
      )}
    >
      {withDot ? <span className={cx("h-1.5 w-1.5 shrink-0 rounded-full", dotColor[variant])} aria-hidden="true" /> : null}
      {children}
    </span>
  );
}
