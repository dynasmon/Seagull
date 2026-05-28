import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Card({
  title,
  right,
  children,
  className,
}: {
  title?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const hasHeader = Boolean(title || right);

  return (
    <section className={cx("ui-card-shell overflow-hidden", className)}>
      {hasHeader && (
        <header className="ui-panel-header">
          <div className="ui-panel-eyebrow truncate">{title}</div>
          {right ? <div className="text-[10.5px] text-muted-foreground">{right}</div> : null}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
