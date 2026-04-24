import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export function Toolbar({
  left,
  right,
  className,
}: {
  left?: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cx(
        "ui-toolbar-shell flex flex-wrap items-center justify-between gap-2",
        className,
      )}
    >
      <div className="flex min-w-0 grow items-center gap-2">{left}</div>
      {right ? (
        <div className="flex shrink-0 items-center gap-2">{right}</div>
      ) : null}
    </div>
  );
}
