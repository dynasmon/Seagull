import type { ReactNode } from "react";
import { EuiEmptyPrompt } from "@elastic/eui";

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
      <EuiEmptyPrompt
        icon={icon ? <span aria-hidden="true">{icon}</span> : undefined}
        color="transparent"
        paddingSize="m"
        titleSize="xs"
        title={<h2>{title}</h2>}
        body={text ? <p>{text}</p> : undefined}
        actions={action ?? undefined}
      />
    </div>
  );
}
