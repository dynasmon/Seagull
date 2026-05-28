import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type StatusVariant =
  | "active"
  | "inactive"
  | "pending"
  | "success"
  | "warning"
  | "danger"
  | "info"
  | "neutral";

const surface: Record<StatusVariant, string> = {
  active: "border-success/40 bg-success/12 text-success",
  inactive: "border-border bg-muted text-muted-foreground",
  pending: "border-warning/40 bg-warning/12 text-warning",
  success: "border-success/40 bg-success/12 text-success",
  warning: "border-warning/40 bg-warning/12 text-warning",
  danger: "border-danger/40 bg-danger/12 text-danger",
  info: "border-info/40 bg-info/12 text-info",
  neutral: "border-border bg-muted text-muted-foreground",
};

const dotColor: Record<StatusVariant, string> = {
  active: "bg-success",
  inactive: "bg-muted-foreground/60",
  pending: "bg-warning",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
  info: "bg-info",
  neutral: "bg-muted-foreground/60",
};

export function StatusPill({
  variant = "neutral",
  children,
  className,
  withDot = false,
  size = "default",
}: {
  variant?: StatusVariant;
  children: ReactNode;
  className?: string;
  withDot?: boolean;
  size?: "default" | "sm";
}) {
  const sizeClass = size === "sm" ? "px-1.5 py-[1px] text-[9.5px]" : "px-2 py-0.5 text-[10px]";
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border font-semibold uppercase tracking-[0.06em]",
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
