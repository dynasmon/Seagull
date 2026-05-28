import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Dot({ state, className }: { state: "online" | "offline" | "disabled"; className?: string }) {
  const cls =
    state === "online"
      ? "bg-success shadow-[0_0_0_3px_rgb(var(--success)/0.18)]"
      : state === "offline"
        ? "bg-warning"
        : "bg-muted-foreground/55";

  return <span className={cx("inline-block h-2.5 w-2.5 rounded-full", cls, className)} aria-hidden="true" />;
}

export function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
      {children}
    </div>
  );
}
