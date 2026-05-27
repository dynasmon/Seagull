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
  active: "border-success/40 bg-success/15 text-success",
  inactive: "border-border bg-muted text-muted-foreground",
  pending: "border-warning/40 bg-warning/15 text-warning",
  success: "border-success/40 bg-success/15 text-success",
  warning: "border-warning/40 bg-warning/15 text-warning",
  danger: "border-danger/40 bg-danger/15 text-danger",
  neutral: "border-border bg-muted text-muted-foreground",
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
        "inline-flex items-center whitespace-nowrap rounded-sm border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em]",
        map[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}
