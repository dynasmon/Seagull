import type { ReactNode } from "react";
import { useEffect, useState } from "react";

import EmptyState from "@/shared/components/EmptyState";
import { cx } from "@/shared/lib/cx";
import useDebouncedValue from "@/shared/hooks/useDebouncedValue";

export function DataViewToolbar({
  left,
  right,
  className
}: {
  left?: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cx("ui-toolbar-shell flex flex-wrap items-center justify-between gap-3", className)}>
      <div className="min-w-0 grow">{left}</div>
      {right ? <div className="shrink-0">{right}</div> : null}
    </div>
  );
}

export function DataViewFilterBar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx("ui-toolbar-shell grid gap-3 md:grid-cols-2 xl:grid-cols-4", className)}>{children}</div>;
}

export function DataFilterGroup({
  label,
  children,
  className
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={cx("block min-w-0", className)}>
      <div className="mb-1 text-[10px] font-mono font-semibold uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
      {children}
    </label>
  );
}

export function DebouncedSearchInput({
  value,
  onChange,
  delayMs = 350,
  placeholder = "Search...",
  ariaLabel = "Search",
  className,
  disabled,
}: {
  value: string;
  onChange: (next: string) => void;
  delayMs?: number;
  placeholder?: string;
  ariaLabel?: string;
  className?: string;
  disabled?: boolean;
}) {
  const [draft, setDraft] = useState(value);
  const debounced = useDebouncedValue(draft, delayMs);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  useEffect(() => {
    if (debounced === value) return;
    onChange(debounced);
  }, [debounced, onChange, value]);

  return (
    <input
      type="search"
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      placeholder={placeholder}
      aria-label={ariaLabel}
      disabled={disabled}
      className={cx("ui-input font-mono text-xs", className)}
    />
  );
}

export function DataLookbackSelect({
  value,
  onChange,
  options,
  className,
  disabled,
}: {
  value: number;
  onChange: (next: number) => void;
  options?: Array<{ label: string; minutes: number }>;
  className?: string;
  disabled?: boolean;
}) {
  const resolvedOptions = options ?? [
    { label: "15 min", minutes: 15 },
    { label: "30 min", minutes: 30 },
    { label: "1 hour", minutes: 60 },
    { label: "6 hours", minutes: 360 },
    { label: "24 hours", minutes: 1440 },
  ];

  return (
    <select
      value={String(value)}
      onChange={(e) => onChange(Number(e.target.value))}
      disabled={disabled}
      className={cx("ui-select font-mono text-xs", className)}
      aria-label="Lookback window"
    >
      {resolvedOptions.map((opt) => (
        <option key={opt.minutes} value={opt.minutes}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}

export function DataStatsStrip({
  stats,
  className
}: {
  stats: Array<{ label: string; value: ReactNode; hint?: ReactNode; tone?: "default" | "success" | "warning" | "danger" | "info" }>;
  className?: string;
}) {
  function toneClass(tone?: "default" | "success" | "warning" | "danger" | "info"): string {
    switch (tone) {
      case "success":
        return "text-success";
      case "warning":
        return "text-warning";
      case "danger":
        return "text-danger";
      case "info":
        return "text-info";
      default:
        return "text-foreground";
    }
  }
  return (
    <div className={cx("grid gap-2 sm:grid-cols-2 xl:grid-cols-4", className)}>
      {stats.map((item) => (
        <div key={item.label} className="ui-card-shell px-3.5 py-3">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{item.label}</div>
          <div className={cx("mt-1 text-lg font-semibold leading-tight tracking-tight", toneClass(item.tone))}>{item.value}</div>
          {item.hint ? <div className="mt-1 text-[10px] text-muted-foreground">{item.hint}</div> : null}
        </div>
      ))}
    </div>
  );
}

export function DataQueryStateBanner({
  message,
  tone = "neutral",
  right,
}: {
  message: ReactNode;
  tone?: "neutral" | "warning" | "danger" | "success";
  right?: ReactNode;
}) {
  const toneClasses =
    tone === "warning"
      ? "border-warning/40 bg-warning/10 text-warning"
      : tone === "danger"
        ? "border-danger/45 bg-danger/10 text-danger"
        : tone === "success"
          ? "border-success/45 bg-success/10 text-success"
          : "border-border/60 bg-muted/30 text-muted-foreground";

  return (
    <div
      className={cx("flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2 text-[11px]", toneClasses)}
      role="status"
      aria-live="polite"
    >
      <div className="font-mono leading-relaxed">{message}</div>
      {right ? <div className="font-mono">{right}</div> : null}
    </div>
  );
}

export function DataTableSkeleton({
  rows = 8,
  columns = 5,
  className,
}: {
  rows?: number;
  columns?: number;
  className?: string;
}) {
  return (
    <div className={cx("ui-card-shell overflow-hidden", className)} aria-hidden="true">
      <div className="animate-pulse">
        <div className="border-b border-border/60 bg-muted/35 px-3 py-2">
          <div className="h-3 w-40 rounded bg-muted/65" />
        </div>
        <div className="space-y-2 p-3">
          {Array.from({ length: rows }).map((_, rowIdx) => (
            <div key={rowIdx} className="grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.max(1, columns)}, minmax(0, 1fr))` }}>
              {Array.from({ length: columns }).map((__, colIdx) => (
                <div key={colIdx} className="h-4 rounded bg-muted/60" />
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function DataEmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="space-y-3">
      <EmptyState title={title} description={description} />
      {action ? <div className="flex justify-center">{action}</div> : null}
    </div>
  );
}

export function DataPaginationFooter({
  totalCount,
  pageSize,
  onPageSizeChange,
  pageSizeOptions = [25, 50, 100, 200],
  hasMore,
  loadingMore,
  onLoadMore,
  loadMoreLabel = "Load more",
  error,
  onRetry,
  className,
}: {
  totalCount: number;
  pageSize: number;
  onPageSizeChange: (next: number) => void;
  pageSizeOptions?: number[];
  hasMore: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
  loadMoreLabel?: string;
  error?: string | null;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div className={cx("ui-toolbar-shell flex flex-wrap items-center justify-between gap-3", className)}>
      <div className="flex flex-wrap items-center gap-3">
        <div className="text-[11px] text-muted-foreground">
          Showing <span className="font-semibold text-foreground">{totalCount}</span> rows
        </div>

        <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <span>Page size</span>
          <select
            value={String(pageSize)}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            className="ui-select h-8 w-auto min-w-[84px] px-2 text-xs"
            aria-label="Rows per page"
          >
            {pageSizeOptions.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="flex items-center gap-2">
        {error ? <span className="text-[11px] text-danger">{error}</span> : null}
        {error && onRetry ? (
          <button type="button" onClick={onRetry} className="ui-btn-secondary h-8 px-2.5 text-xs">
            Retry
          </button>
        ) : null}

        {hasMore ? (
          <button
            type="button"
            onClick={onLoadMore}
            disabled={loadingMore || !onLoadMore}
            className={cx("ui-btn h-8 px-3 text-xs", (loadingMore || !onLoadMore) && "cursor-not-allowed opacity-65")}
          >
            {loadingMore ? "Loading..." : loadMoreLabel}
          </button>
        ) : (
          <span className="text-[11px] text-muted-foreground">No more rows</span>
        )}
      </div>
    </div>
  );
}
