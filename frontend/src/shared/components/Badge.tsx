import type { ReactNode } from "react";

type Variant = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const map: Record<Variant, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/30",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  info: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  neutral: "bg-muted/10 text-muted-foreground border-border/60"
};

export function Badge({
  children,
  variant = "neutral"
}: {
  children: ReactNode;
  variant?: Variant;
}) {
  return (
    <span className={`inline-flex items-center border px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest ${map[variant]}`}>
      {children}
    </span>
  );
}
