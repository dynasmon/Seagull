import type { CSSProperties, ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Panel({
  title,
  subtitle,
  actions,
  children,
  compact = false,
  padded = true,
  scrollY = false,
  className,
  style,
  bodyClassName,
  bodyRef,
  tone = "default",
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  compact?: boolean;
  padded?: boolean;
  scrollY?: boolean;
  className?: string;
  style?: CSSProperties;
  bodyClassName?: string;
  bodyRef?: React.Ref<HTMLDivElement>;
  tone?: "default" | "muted" | "raised";
}) {
  const hasHeader = Boolean(title || subtitle || actions);
  const shellTone =
    tone === "raised"
      ? "ui-card-shell shadow-elevated"
      : tone === "muted"
        ? "rounded-lg border border-border bg-surface-2/70"
        : "ui-card-shell";
  const padClass = padded ? (compact ? "p-3" : "p-4") : "";

  return (
    <section className={cx(shellTone, "flex flex-col overflow-hidden", className)} style={style}>
      {hasHeader && (
        <header className="ui-panel-header shrink-0">
          <div className="min-w-0">
            {title ? <div className="ui-panel-eyebrow truncate">{title}</div> : null}
            {subtitle ? <div className="ui-panel-subtitle">{subtitle}</div> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </header>
      )}
      <div
        ref={bodyRef}
        className={cx(padClass, "flex-1 min-h-0", scrollY && "overflow-y-auto", bodyClassName)}
      >
        {children}
      </div>
    </section>
  );
}
