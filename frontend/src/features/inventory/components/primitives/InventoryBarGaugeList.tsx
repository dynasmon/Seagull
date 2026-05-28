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

export function InventoryBarGaugeList({
  title,
  items,
  onPick,
  maxItems = 12,
  valueFormatter,
}: InventoryBarGaugeListProps) {
  const sliced = items.slice(0, maxItems);
  const max = Math.max(1, ...sliced.map((i) => Number(i.value) || 0));

  return (
    <div className="space-y-2">
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{title}</div>

      <div className="space-y-1.5">
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
                "block w-full rounded-md border border-border bg-card px-3 py-2 text-left transition-colors",
                clickable ? "hover:border-primary/30 hover:bg-surface-2/70" : "cursor-default",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35",
              )}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="truncate font-mono text-[11.5px] text-foreground">{row.metric}</div>
                <div className="shrink-0 font-mono text-[11px] text-muted-foreground">
                  {valueFormatter ? valueFormatter(row.value) : String(row.value)}
                </div>
              </div>
              <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-muted/40">
                <div className="h-full rounded-full bg-primary/65" style={{ width: `${pct}%` }} />
              </div>
            </button>
          );
        })}

        {sliced.length === 0 ? (
          <div className="rounded-md border border-border bg-surface-2/40 px-3 py-2 text-[11px] text-muted-foreground">
            No data.
          </div>
        ) : null}
      </div>
    </div>
  );
}
