import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

type StatusTone = "error" | "warning" | "info";

const toneClassName: Record<StatusTone, string> = {
  error: "border-destructive/30 bg-destructive/10 text-destructive",
  warning: "border-yellow-500/30 bg-yellow-500/10 text-yellow-200",
  info: "border-border/60 bg-background/40 text-muted-foreground"
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
    <div className={cx("rounded-xl border px-4 py-3 text-sm", toneClassName[tone])}>
      <div className="flex items-center justify-between gap-3">
        <div>{children}</div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
    </div>
  );
}
