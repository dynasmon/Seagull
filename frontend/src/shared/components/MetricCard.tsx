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
  className,
}: {
  title: string;
  value?: ReactNode;
  helper?: ReactNode;
  loading?: boolean;
  tone?: MetricTone;
  className?: string;
}) {
  return (
    <div className={cx("ui-card-shell px-3 py-2.5", className)}>
      <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
        {title}
      </div>
      <div className={cx("mt-1 text-lg font-semibold leading-tight", toneClasses[tone])}>
        {loading ? (
          <span className="inline-block h-5 w-16 animate-pulse rounded bg-muted/60" aria-label="Loading" />
        ) : value != null ? (
          value
        ) : (
          <span className="text-muted-foreground/60">—</span>
        )}
      </div>
      {helper ? (
        <div className="mt-1 text-[11px] text-muted-foreground">{helper}</div>
      ) : null}
    </div>
  );
}
