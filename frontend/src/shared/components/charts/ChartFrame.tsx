import type { ReactNode } from "react";

import "@elastic/charts/dist/theme_light.css";

import { cx } from "@/shared/lib/cx";

export interface ChartFrameProps {
  height: number;
  minWidth?: number;
  allowHorizontalScroll?: boolean;
  isEmpty?: boolean;
  emptyLabel?: string;
  className?: string;
  children: ReactNode;
}

export function ChartFrame({
  height,
  minWidth = 0,
  allowHorizontalScroll = false,
  isEmpty = false,
  emptyLabel = "No data in this window",
  className,
  children,
}: ChartFrameProps) {
  if (isEmpty) {
    return (
      <div
        className={cx("flex items-center justify-center rounded-md", className)}
        style={{ height }}
      >
        <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
          {emptyLabel}
        </span>
      </div>
    );
  }

  if (allowHorizontalScroll) {
    return (
      <div className={cx("w-full min-w-0 overflow-x-auto", className)}>
        <div style={{ minWidth, height }}>{children}</div>
      </div>
    );
  }

  return (
    <div className={cx("w-full min-w-0", className)} style={{ height }}>
      {children}
    </div>
  );
}
