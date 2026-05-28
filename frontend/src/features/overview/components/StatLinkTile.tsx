import { Link } from "react-router-dom";

import { cx } from "@/shared/lib/cx";

export function StatLinkTile({
  to,
  label,
  value,
  description,
  className,
}: {
  to: string;
  label: string;
  value: string;
  description?: string;
  className?: string;
}) {
  return (
    <Link
      to={to}
      className={cx(
        "ui-card-shell flex flex-col gap-1 px-3 py-2.5 transition-colors",
        "hover:border-primary/35 hover:bg-surface-2/70",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35",
        className,
      )}
    >
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
      <div className="text-sm font-semibold leading-tight tracking-tight text-foreground">{value}</div>
      {description ? <div className="text-[10px] leading-snug text-muted-foreground">{description}</div> : null}
    </Link>
  );
}
