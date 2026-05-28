import { useMemo, useState } from "react";

import { cx } from "@/shared/lib/cx";

type Row = { key: string; count: number };

type NewTypeRow = { key?: string; type?: string; count: number };

type Props = {
  title?: string;

  rows?: Row[];
  selectedKey?: string | null;
  onSelect?: (key: string) => void;

  activeType?: string | null;
  types?: NewTypeRow[];
  onSelectType?: (t: string) => void;
  onClearType?: () => void;
};

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      className={cx("h-3 w-3 shrink-0 transition-transform", open ? "rotate-90" : "rotate-0")}
      viewBox="0 0 12 12"
      aria-hidden="true"
    >
      <path
        d="M4 2.5 8 6l-4 3.5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  );
}

function normalizeRowsFromTypes(types: NewTypeRow[] | undefined | null): Row[] {
  const list = (types ?? []).map((t) => ({
    key: (t.key ?? t.type ?? "").trim(),
    count: Number.isFinite(Number((t as any).count)) ? Number((t as any).count) : 0,
  }));
  return list.filter((r) => r.key);
}

export default function EventExplorer(props: Props) {
  const { title = "Explorer", rows, selectedKey, onSelect, activeType, types, onSelectType, onClearType } = props;

  const [open, setOpen] = useState(true);

  const isNew =
    typeof onSelectType === "function" ||
    typeof onClearType === "function" ||
    Array.isArray(types) ||
    activeType !== undefined;

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
        if (!onClearType) onSelectType?.("");
        return;
      }
      onSelectType?.(k);
      return;
    }

    onSelect?.(k);
  }

  return (
    <div className="ui-card-shell">
      <button
        type="button"
        onClick={() => setOpen((p) => !p)}
        className="flex w-full items-center justify-between gap-2 border-b border-border bg-surface-2/70 px-3 py-2 text-left transition-colors hover:bg-surface-2"
      >
        <div className="flex items-center gap-2">
          <Chevron open={open} />
          <span className="text-[10.5px] font-semibold uppercase tracking-[0.12em] text-foreground/85">{title}</span>
        </div>
        <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">types</span>
      </button>

      {open && (
        <div className="p-2">
          <div className="space-y-1">
            {items.map((r) => {
              const active = effectiveSelectedKey === (r.key || "");
              const label = r.key ? r.key : "All events";
              return (
                <button
                  key={r.key || "__all__"}
                  type="button"
                  onClick={() => handleSelect(r.key)}
                  className={cx(
                    "flex w-full items-center justify-between gap-3 rounded-md border px-3 py-1.5 text-left text-sm transition-colors",
                    active
                      ? "border-primary/55 bg-primary/[0.08] text-foreground"
                      : "border-transparent text-muted-foreground hover:border-border hover:bg-surface-2/70 hover:text-foreground",
                  )}
                >
                  <span className="truncate font-mono text-[12px]">{label}</span>
                  <span className="shrink-0 font-mono text-[11px] text-muted-foreground">{r.count}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
