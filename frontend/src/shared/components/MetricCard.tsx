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

const toneAccentClasses: Record<MetricTone, string> = {
  default: "bg-muted/50",
  success: "bg-success/15 text-success",
  warning: "bg-warning/15 text-warning",
  danger: "bg-danger/15 text-danger",
  info: "bg-info/15 text-info",
};

export function MetricCard({
  title,
  value,
  helper,
  loading = false,
  tone = "default",
  size = "default",
  trend,
  icon,
  className,
}: {
  title: string;
  value?: ReactNode;
  helper?: ReactNode;
  loading?: boolean;
  tone?: MetricTone;
  size?: "default" | "sm";
  trend?: ReactNode;
  icon?: ReactNode;
  className?: string;
}) {
  const padClass = size === "sm" ? "px-3 py-2.5" : "px-4 py-3.5";
  const valClass =
    size === "sm"
      ? "text-sm font-semibold leading-tight tracking-tight"
      : "text-xl font-semibold leading-tight tracking-tight";

  return (
    <div className={cx("ui-card-shell flex min-w-0 flex-col", padClass, className)}>
      <div className="flex items-start justify-between gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          {title}
        </div>
        {icon ? (
          <span
            className={cx(
              "inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md",
              toneAccentClasses[tone],
            )}
            aria-hidden="true"
          >
            {icon}
          </span>
        ) : null}
      </div>

      <div className={cx("mt-1.5", valClass, toneClasses[tone])}>
        {loading ? (
          <span className="inline-block h-5 w-16 animate-pulse rounded bg-muted/60" aria-label="Loading" />
        ) : value != null ? (
          value
        ) : (
          <span className="text-muted-foreground/60">—</span>
        )}
      </div>

      {helper || trend ? (
        <div className="mt-1 flex flex-wrap items-center justify-between gap-1 text-[10px] text-muted-foreground">
          {helper ? <div className="min-w-0 truncate">{helper}</div> : <span />}
          {trend ? <div className="shrink-0">{trend}</div> : null}
        </div>
      ) : null}
    </div>
  );
}
