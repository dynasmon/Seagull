import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type StatusVariant =
  | "active"
  | "inactive"
  | "pending"
  | "success"
  | "warning"
  | "danger"
  | "neutral";

const map: Record<StatusVariant, string> = {
  active: "border-success/45 bg-success/10 text-success",
  inactive: "border-border/70 bg-muted/40 text-muted-foreground",
  pending: "border-warning/45 bg-warning/10 text-warning",
  success: "border-success/45 bg-success/10 text-success",
  warning: "border-warning/45 bg-warning/10 text-warning",
  danger: "border-danger/45 bg-danger/10 text-danger",
  neutral: "border-border/70 bg-muted/40 text-muted-foreground",
};

export function StatusPill({
  variant = "neutral",
  children,
  className,
}: {
  variant?: StatusVariant;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cx(
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em]",
        map[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}
