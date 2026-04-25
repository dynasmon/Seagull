import type { CSSProperties, ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Panel({
  title,
  subtitle,
  actions,
  children,
  compact = false,
  scrollY = false,
  className,
  style,
  bodyClassName,
  bodyRef,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  compact?: boolean;
  scrollY?: boolean;
  className?: string;
  style?: CSSProperties;
  bodyClassName?: string;
  bodyRef?: React.Ref<HTMLDivElement>;
}) {
  const hasHeader = Boolean(title || subtitle || actions);

  return (
    <section className={cx("ui-card-shell flex flex-col overflow-hidden", className)} style={style}>
      {hasHeader && (
        <div className="flex shrink-0 items-start justify-between gap-3 border-b border-border/80 bg-surface-2/70 px-4 py-3">
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
      <div
        ref={bodyRef}
        className={cx(compact ? "p-3" : "p-4", "flex-1 min-h-0", scrollY && "overflow-y-auto", bodyClassName)}
      >
        {children}
      </div>
    </section>
  );
}
