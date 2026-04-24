import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type AlertTone = "info" | "success" | "warning" | "danger";

const toneClasses: Record<AlertTone, string> = {
  info: "border-border/70 bg-muted/35 text-muted-foreground",
  success: "border-success/45 bg-success/10 text-success",
  warning: "border-warning/45 bg-warning/10 text-warning",
  danger: "border-danger/45 bg-danger/10 text-danger",
};

export function InlineAlert({
  tone = "info",
  children,
  className,
}: {
  tone?: AlertTone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cx("rounded-md border px-3 py-2.5 text-sm", toneClasses[tone], className)}
    >
      {children}
    </div>
  );
}
