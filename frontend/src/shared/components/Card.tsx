import React from "react";

function cx(...v: Array<string | false | undefined>) {
  return v.filter(Boolean).join(" ");
}

export function Card({
  title,
  right,
  children,
  className
}: {
  title?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cx(
        "rounded-lg border border-[var(--border)] bg-[var(--panel)]",
        "shadow-sm",
        className
      )}
    >
      {(title || right) && (
        <header className="flex items-center justify-between px-4 py-3">
          <div className="text-sm font-semibold">{title}</div>
          <div className="text-xs text-[var(--muted)]">{right}</div>
        </header>
      )}
      <div className={cx("px-4", title || right ? "pb-4" : "py-4")}>{children}</div>
    </section>
  );
}
