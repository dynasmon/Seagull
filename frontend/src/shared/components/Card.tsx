import type { ReactNode } from "react";
import { EuiPanel } from "@elastic/eui";

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
    <EuiPanel hasBorder hasShadow={false} paddingSize="none" className={cx("overflow-hidden", className)}>
      {hasHeader && (
        <header className="ui-panel-header">
          <div className="ui-panel-eyebrow truncate">{title}</div>
          {right ? <div className="text-[10.5px] text-muted-foreground">{right}</div> : null}
        </header>
      )}
      <div className="p-4">{children}</div>
    </EuiPanel>
  );
}
