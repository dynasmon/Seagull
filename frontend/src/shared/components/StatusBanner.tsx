import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

type StatusTone = "error" | "warning" | "info" | "success";

const toneClassName: Record<StatusTone, string> = {
  error: "border-danger/45 bg-danger/10 text-danger",
  warning: "border-warning/45 bg-warning/10 text-warning",
  info: "border-border/80 bg-surface-2/70 text-muted-foreground",
  success: "border-success/45 bg-success/10 text-success",
};

const dotClass: Record<StatusTone, string> = {
  error: "bg-danger",
  warning: "bg-warning",
  info: "bg-muted-foreground/60",
  success: "bg-success",
};

export default function StatusBanner({
  tone = "info",
  children,
  action,
  className,
}: {
  tone?: StatusTone;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx("rounded-md border px-3.5 py-2.5 text-[12px]", toneClassName[tone], className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <span className={cx("mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full", dotClass[tone])} aria-hidden="true" />
          <div className="min-w-0 leading-relaxed">{children}</div>
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
    </div>
  );
}
