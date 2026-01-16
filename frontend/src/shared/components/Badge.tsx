import React from "react";

type Variant = "critical" | "high" | "medium" | "low" | "info" | "neutral";

const map: Record<Variant, string> = {
  critical: "bg-red-500/15 text-red-500 border-red-500/30",
  high: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-600 border-yellow-500/30",
  low: "bg-green-500/15 text-green-600 border-green-500/30",
  info: "bg-blue-500/15 text-blue-500 border-blue-500/30",
  neutral: "bg-white/10 text-[var(--muted)] border-[var(--border)]"
};

export function Badge({
  children,
  variant = "neutral"
}: {
  children: React.ReactNode;
  variant?: Variant;
}) {
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs ${map[variant]}`}>
      {children}
    </span>
  );
}
