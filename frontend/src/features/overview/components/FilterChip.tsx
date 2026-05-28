import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cx(
        "inline-flex h-6 items-center rounded-full border px-2.5 text-[10px] font-semibold uppercase tracking-[0.12em] transition-colors",
        active
          ? "border-primary/55 bg-primary/12 text-primary"
          : "border-border bg-card text-muted-foreground hover:border-primary/30 hover:bg-muted hover:text-foreground",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35",
      )}
    >
      {children}
    </button>
  );
}
