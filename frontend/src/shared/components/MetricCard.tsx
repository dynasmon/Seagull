import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type MetricTone = "default" | "success" | "warning" | "danger" | "info";

const toneClasses: Record<MetricTone, string> = {
  default: "text-foreground",
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
  info: "text-info",
};

export function MetricCard({
  title,
  value,
  helper,
  loading = false,
  tone = "default",
  size = "default",
  className,
}: {
  title: string;
  value?: ReactNode;
  helper?: ReactNode;
  loading?: boolean;
  tone?: MetricTone;
  size?: "default" | "sm";
  className?: string;
}) {
  const padClass = size === "sm" ? "px-3 py-2.5" : "px-4 py-3.5";
  const valClass = size === "sm" ? "text-sm font-semibold leading-tight tracking-tight" : "text-xl font-semibold leading-tight tracking-tight";

  return (
    <div className={cx("ui-card-shell", padClass, className)}>
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-muted-foreground">
        {title}
      </div>
      <div className={cx("mt-1", valClass, toneClasses[tone])}>
        {loading ? (
          <span className="inline-block h-5 w-16 animate-pulse rounded bg-muted/60" aria-label="Loading" />
        ) : value != null ? (
          value
        ) : (
          <span className="text-muted-foreground/60">—</span>
        )}
      </div>
      {helper ? (
        <div className="mt-1 text-[10px] text-muted-foreground">{helper}</div>
      ) : null}
    </div>
  );
}
