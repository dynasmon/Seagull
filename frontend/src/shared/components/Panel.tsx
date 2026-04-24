import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Panel({
  title,
  subtitle,
  actions,
  children,
  compact = false,
  className,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  compact?: boolean;
  className?: string;
}) {
  const hasHeader = Boolean(title || subtitle || actions);

  return (
    <section className={cx("ui-card-shell overflow-hidden", className)}>
      {hasHeader && (
        <div className="flex items-start justify-between gap-3 border-b border-border/80 bg-surface-2/70 px-4 py-3">
          <div className="min-w-0">
            {title ? (
              <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
                {title}
              </div>
            ) : null}
            {subtitle ? (
              <div className="mt-1 text-[12px] text-muted-foreground">{subtitle}</div>
            ) : null}
          </div>
          {actions ? (
            <div className="flex shrink-0 items-center gap-2">{actions}</div>
          ) : null}
        </div>
      )}
      <div className={compact ? "p-3" : "p-4"}>{children}</div>
    </section>
  );
}
