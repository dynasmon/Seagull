import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { cx } from "@/shared/lib/cx";

export function EventsLinkButton({
  to,
  title,
  children,
  className,
}: {
  to: string;
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Link to={to} title={title} className={cx("ui-btn h-8", className)}>
      {children}
    </Link>
  );
}
