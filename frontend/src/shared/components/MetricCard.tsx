import type { ReactNode } from "react";
import { EuiPanel, EuiStat } from "@elastic/eui";

import { cx } from "@/shared/lib/cx";

export type MetricTone = "default" | "success" | "warning" | "danger" | "info";

const titleColorByTone: Record<MetricTone, string> = {
  default: "default",
  success: "success",
  warning: "warning",
  danger: "danger",
  info: "primary",
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
  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize={size === "sm" ? "s" : "m"} className={cx("min-w-0", className)}>
      <div className="flex items-start justify-between gap-2">
        <EuiStat
          title={value ?? "—"}
          description={title}
          titleColor={titleColorByTone[tone]}
          titleSize={size === "sm" ? "s" : "m"}
          isLoading={loading}
          reverse
        />
        {icon ? <span aria-hidden="true" className="shrink-0">{icon}</span> : null}
      </div>
      {helper || trend ? (
        <div className="mt-1.5 flex flex-wrap items-center justify-between gap-1 text-[10px] text-muted-foreground">
          {helper ? <div className="min-w-0 truncate">{helper}</div> : <span />}
          {trend ? <div className="shrink-0">{trend}</div> : null}
        </div>
      ) : null}
    </EuiPanel>
  );
}
