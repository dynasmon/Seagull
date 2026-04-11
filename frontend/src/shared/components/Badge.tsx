import type { ReactNode } from "react";

type Variant = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const map: Record<Variant, string> = {
  critical: "border-severity-critical/45 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/45 bg-severity-high/10 text-severity-high",
  medium: "border-severity-medium/45 bg-severity-medium/10 text-severity-medium",
  low: "border-severity-low/45 bg-severity-low/10 text-severity-low",
  info: "border-info/45 bg-info/10 text-info",
  neutral: "border-border/70 bg-muted/40 text-muted-foreground"
};

export function Badge({
  children,
  variant = "neutral"
}: {
  children: ReactNode;
  variant?: Variant;
}) {
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-[0.06em] ${map[variant]}`}>
      {children}
    </span>
  );
}
