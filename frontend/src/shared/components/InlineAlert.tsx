import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type AlertTone = "info" | "success" | "warning" | "danger";

const toneClasses: Record<AlertTone, string> = {
  info: "border-border/70 bg-muted/35 text-muted-foreground",
  success: "border-success/45 bg-success/10 text-success",
  warning: "border-warning/45 bg-warning/10 text-warning",
  danger: "border-danger/45 bg-danger/10 text-danger",
};

const accentClasses: Record<AlertTone, string> = {
  info: "bg-muted-foreground/15 text-muted-foreground",
  success: "bg-success/20 text-success",
  warning: "bg-warning/20 text-warning",
  danger: "bg-danger/20 text-danger",
};

function ToneIcon({ tone }: { tone: AlertTone }) {
  if (tone === "success") {
    return (
      <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
        <path d="M3.5 8.5 7 12l6-7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none" />
      </svg>
    );
  }
  if (tone === "warning") {
    return (
      <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
        <path d="M8 3.5v5M8 11.5h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" />
      </svg>
    );
  }
  if (tone === "danger") {
    return (
      <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
        <path d="M5 5l6 6M11 5l-6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
      <path d="M8 5.5v3.5M8 11.5h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" fill="none" />
    </svg>
  );
}

export function InlineAlert({
  tone = "info",
  children,
  className,
  showIcon = true,
}: {
  tone?: AlertTone;
  children: ReactNode;
  className?: string;
  showIcon?: boolean;
}) {
  return (
    <div role="alert" className={cx("flex items-start gap-2.5 rounded-md border px-3 py-2.5 text-sm", toneClasses[tone], className)}>
      {showIcon ? (
        <span
          className={cx(
            "mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full",
            accentClasses[tone],
          )}
          aria-hidden="true"
        >
          <ToneIcon tone={tone} />
        </span>
      ) : null}
      <div className="min-w-0 flex-1 leading-relaxed">{children}</div>
    </div>
  );
}
