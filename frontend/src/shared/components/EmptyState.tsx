
import type { ReactNode } from "react";
import { cx } from "@/shared/lib/cx";

export default function EmptyState({
  title,
  hint,
  description
}: {
  title: string;
  hint?: string | ReactNode;
  description?: string | ReactNode;
}) {
  const text = description ?? hint;

  return (
    <div className={cx("flex h-full w-full items-center justify-center")}>
      <div className="ui-empty-state max-w-[560px]">
        <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-primary">Empty</div>
        <div className="mt-2 text-base font-semibold tracking-tight text-foreground">{title}</div>
        {text ? <div className="mt-2 text-[12px] text-muted-foreground">{text}</div> : null}
      </div>
    </div>
  );
}
