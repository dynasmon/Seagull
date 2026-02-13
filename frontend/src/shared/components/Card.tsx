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
        "border border-border/60 bg-background/70 backdrop-blur-sm",
        className
      )}
    >
      {hasHeader && (
        <header className="flex items-center justify-between border-b border-border/60 bg-muted/10 px-4 py-2">
          <div className="text-xs font-mono font-bold uppercase tracking-widest text-primary/90">
            {title}
          </div>
          {right && (
            <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
              {right}
            </div>
          )}
        </header>
      )}
      <div className={cx("p-4", hasHeader ? "" : "")}>{children}</div>
    </section>
  );
}
