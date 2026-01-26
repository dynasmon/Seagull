import { useMemo, useState } from "react";

import { cx } from "@/shared/lib/cx";

type Row = { key: string; count: number };

type NewTypeRow = { key?: string; type?: string; count: number };

type Props = {
  title?: string;

  // Legacy API (older pages)
  rows?: Row[];
  selectedKey?: string | null;
  onSelect?: (key: string) => void;

  // New API (events page v2)
  activeType?: string | null;
  types?: NewTypeRow[];
  onSelectType?: (t: string) => void;
  onClearType?: () => void;
};

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

function normalizeRowsFromTypes(types: NewTypeRow[] | undefined | null): Row[] {
  const list = (types ?? []).map((t) => ({
    key: (t.key ?? t.type ?? "").trim(),
    count: Number.isFinite(Number((t as any).count)) ? Number((t as any).count) : 0
  }));
  return list.filter((r) => r.key);
}

export default function EventExplorer(props: Props) {
  const {
    title = "Explorer",
    rows,
    selectedKey,
    onSelect,
    activeType,
    types,
    onSelectType,
    onClearType
  } = props;

  const [open, setOpen] = useState(true);

  // Detect the "new" contract by presence of any of the new props.
  const isNew = typeof onSelectType === "function" || typeof onClearType === "function" || Array.isArray(types) || activeType !== undefined;

  const effectiveRows: Row[] = useMemo(() => {
    return isNew ? normalizeRowsFromTypes(types) : (rows ?? []);
  }, [isNew, types, rows]);

  const items = useMemo(() => {
    const total = (effectiveRows ?? []).reduce((acc, r) => acc + (r.count || 0), 0);
    const base: Row[] = [{ key: "", count: total }, ...(effectiveRows ?? [])];
    return base;
  }, [effectiveRows]);

  const effectiveSelectedKey = (isNew ? (activeType ?? "") : (selectedKey ?? "")) || "";

  function handleSelect(key: string) {
    const k = (key ?? "").trim();

    if (isNew) {
      if (!k) {
        onClearType?.();
        // If the caller didn't provide onClearType, we still call onSelectType("") as a fallback.
        if (!onClearType) onSelectType?.("");
        return;
      }
      onSelectType?.(k);
      return;
    }

    onSelect?.(k);
  }

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
            const active = effectiveSelectedKey === (r.key || "");
            const label = r.key ? r.key : "All events";
            return (
              <button
                key={r.key || "__all__"}
                type="button"
                onClick={() => handleSelect(r.key)}
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
