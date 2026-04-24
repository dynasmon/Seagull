import type { ReactNode } from "react";

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
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const hasHeader = Boolean(title || right);

  return (
    <section
      className={cx(
        "ui-card-shell overflow-hidden",
        className
      )}
    >
      {hasHeader && (
        <header className="flex items-center justify-between border-b border-border/80 bg-surface-2/70 px-4 py-2.5">
          <div className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
            {title}
          </div>
          {right && (
            <div className="text-[10px] text-muted-foreground">
              {right}
            </div>
          )}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}
