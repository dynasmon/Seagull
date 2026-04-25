import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Dot({ state }: { state: "online" | "offline" | "disabled" }) {
  const cls =
    state === "online"
      ? "bg-success shadow-[0_0_10px_rgb(var(--success)/0.45)]"
      : state === "offline"
        ? "bg-warning"
        : "bg-muted-foreground/50";

  return <span className={cx("inline-block h-2.5 w-2.5 rounded-full", cls)} />;
}

export function FieldLabel({ children }: { children: ReactNode }) {
  return <div className="text-[10px] font-mono font-bold uppercase tracking-[0.32em] text-muted-foreground">{children}</div>;
}
