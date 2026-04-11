import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

type StatusTone = "error" | "warning" | "info";

const toneClassName: Record<StatusTone, string> = {
  error: "border-danger/45 bg-danger/10 text-danger",
  warning: "border-warning/45 bg-warning/10 text-warning",
  info: "border-border/70 bg-muted/35 text-muted-foreground"
};

export default function StatusBanner({
  tone = "info",
  children,
  action
}: {
  tone?: StatusTone;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className={cx("rounded-lg border px-4 py-3 text-sm", toneClassName[tone])}>
      <div className="flex items-center justify-between gap-3">
        <div>{children}</div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
    </div>
  );
}
