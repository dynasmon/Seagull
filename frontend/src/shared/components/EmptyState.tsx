
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
      <div className="max-w-[520px] rounded-xl border border-border/60 bg-card/10 backdrop-blur-md px-6 py-8 text-center">
        <div className="text-base font-semibold">{title}</div>
        {text ? <div className="mt-2 text-sm text-muted-foreground">{text}</div> : null}
      </div>
    </div>
  );
}
