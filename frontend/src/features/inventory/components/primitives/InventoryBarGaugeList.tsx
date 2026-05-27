import { cx } from "@/shared/lib/cx";

interface BarGaugeItem {
  metric: string;
  value: number;
}

interface InventoryBarGaugeListProps {
  title: string;
  items: BarGaugeItem[];
  onPick?: (metric: string) => void;
  maxItems?: number;
  valueFormatter?: (v: number) => string;
}

export function InventoryBarGaugeList({ title, items, onPick, maxItems = 12, valueFormatter }: InventoryBarGaugeListProps) {
  const sliced = items.slice(0, maxItems);
  const max = Math.max(1, ...sliced.map((i) => Number(i.value) || 0));

  return (
    <div className="space-y-3">
      <div className="text-[10px] font-mono font-bold uppercase tracking-[0.35em] text-muted-foreground">{title}</div>

      <div className="space-y-2">
        {sliced.map((row) => {
          const pct = Math.max(0, Math.min(100, (row.value / max) * 100));
          const clickable = Boolean(onPick);
          return (
            <button
              key={row.metric}
              type="button"
              disabled={!clickable}
              onClick={() => onPick?.(row.metric)}
              className={cx(
                "w-full text-left rounded-md border border-border/60 bg-background/40 px-3 py-2",
                clickable ? "hover:bg-muted/10" : "cursor-default",
                "focus:outline-none focus:ring-2 focus:ring-primary/30"
              )}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="truncate text-[11px] font-mono text-foreground">{row.metric}</div>
                <div className="shrink-0 text-[11px] font-mono text-muted-foreground">
                  {valueFormatter ? valueFormatter(row.value) : String(row.value)}
                </div>
              </div>
              <div className="mt-2 h-2 w-full rounded bg-muted/20 overflow-hidden">
                <div className="h-full bg-primary/60" style={{ width: `${pct}%` }} />
              </div>
            </button>
          );
        })}

        {sliced.length === 0 ? (
          <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2 text-[11px] text-muted-foreground">
            No data.
          </div>
        ) : null}
      </div>
    </div>
  );
}
