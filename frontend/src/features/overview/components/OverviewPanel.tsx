import type { CSSProperties, ReactNode } from "react";

import { Panel } from "@/shared/components/Panel";
import { cx } from "@/shared/lib/cx";

export function OverviewPanel({
  title,
  children,
  right,
  className,
  isCritical = false,
  scrollY = false,
  bodyClassName,
  style,
}: {
  title: string;
  children: ReactNode;
  right?: ReactNode;
  className?: string;
  isCritical?: boolean;
  scrollY?: boolean;
  bodyClassName?: string;
  style?: CSSProperties;
}) {
  return (
    <Panel
      title={title}
      actions={right}
      scrollY={scrollY}
      style={style}
      className={cx(isCritical && "border-danger/40 shadow-soft", className)}
      bodyClassName={cx("flex flex-col gap-3", bodyClassName)}
    >
      {children}
    </Panel>
  );
}
