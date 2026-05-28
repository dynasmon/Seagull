import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export default function EmptyState({
  title,
  hint,
  description,
  icon,
  action,
  className,
}: {
  title: string;
  hint?: string | ReactNode;
  description?: string | ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  const text = description ?? hint;

  return (
    <div className={cx("flex h-full w-full items-center justify-center", className)}>
      <div className="ui-empty-state max-w-[560px]">
        {icon ? (
          <div className="mx-auto mb-3 inline-flex h-10 w-10 items-center justify-center rounded-full border border-border bg-card text-muted-foreground">
            {icon}
          </div>
        ) : null}
        <div className="text-[14px] font-semibold tracking-tight text-foreground">{title}</div>
        {text ? <div className="mt-1.5 text-[12px] leading-relaxed text-muted-foreground">{text}</div> : null}
        {action ? <div className="mt-3 inline-flex">{action}</div> : null}
      </div>
    </div>
  );
}
