import { useMemo, useState } from "react";

import { cx } from "@/shared/lib/cx";

type Row = { key: string; count: number };

function ActiveBar({ active }: { active: boolean }) {
  if (!active) return null;
  return <span className="absolute left-0 top-1 bottom-1 w-[3px] rounded-r bg-primary" />;
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg className={cx("h-4 w-4 transition-transform", open ? "rotate-90" : "rotate-0")} viewBox="0 0 24 24" fill="none">
      <path d="M9 18l6-6-6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function EventExplorer({
  title = "Explorer",
  rows,
  selectedKey,
  onSelect
}: {
  title?: string;
  rows: Row[];
  selectedKey: string;
  onSelect: (key: string) => void;
}) {
  const [open, setOpen] = useState(true);

  const items = useMemo(() => {
    const base: Row[] = [{ key: "", count: rows.reduce((acc, r) => acc + (r.count || 0), 0) }, ...rows];
    return base;
  }, [rows]);

  return (
    <div className="border border-border/60 bg-background/70 backdrop-blur-sm">
      <button
        type="button"
        onClick={() => setOpen((p) => !p)}
        className="w-full flex items-center justify-between gap-2 border-b border-border/60 bg-muted/10 px-3 py-2"
      >
        <div className="flex items-center gap-2">
          <Chevron open={open} />
          <span className="text-xs font-bold uppercase tracking-widest font-mono text-primary/90">{title}</span>
        </div>
        <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider">types</span>
      </button>

      {open && (
        <div className="py-2">
          {items.map((r) => {
            const active = (selectedKey || "") === (r.key || "");
            const label = r.key ? r.key : "All events";
            return (
              <button
                key={r.key || "__all__"}
                type="button"
                onClick={() => onSelect(r.key)}
                className={cx(
                  "relative w-full px-3 py-2 flex items-center justify-between gap-3 text-left text-sm transition-colors",
                  active ? "bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-muted/10 hover:text-foreground"
                )}
              >
                <ActiveBar active={active} />
                <span className="truncate">{label}</span>
                <span className="shrink-0 text-[10px] font-mono text-muted-foreground">{r.count}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
