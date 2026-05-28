import { Link } from "react-router-dom";

import { cx } from "@/shared/lib/cx";

export function QuickPivot({
  to,
  label,
  hint,
}: {
  to: string;
  label: string;
  hint: string;
}) {
  return (
    <Link
      to={to}
      className={cx(
        "group ui-card-shell flex flex-col gap-1 px-3.5 py-2.5 transition-colors",
        "hover:border-primary/35 hover:bg-surface-2/70",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35",
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
        <svg viewBox="0 0 12 12" className="h-3 w-3 text-muted-foreground transition-colors group-hover:text-primary" aria-hidden="true">
          <path d="M4 2.5 8 6l-4 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" fill="none" />
        </svg>
      </div>
      <div className="text-xs leading-snug text-foreground/85">{hint}</div>
    </Link>
  );
}
