import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { EuiCallOut, EuiFieldSearch, EuiPanel, EuiSelect, EuiSkeletonRectangle, EuiStat } from "@elastic/eui";

import { Button } from "@/shared/components/Button";
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
    <EuiPanel hasBorder hasShadow={false} paddingSize="none" borderRadius="m" className={className}>
      <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-2.5">
        <div className="min-w-0 grow">{left}</div>
        {right ? <div className="shrink-0">{right}</div> : null}
      </div>
    </EuiPanel>
  );
}

export function DataViewFilterBar({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="none" borderRadius="m">
      <div className={cx("grid gap-3 px-3 py-2.5 md:grid-cols-2 xl:grid-cols-4", className)}>{children}</div>
    </EuiPanel>
  );
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
  fullWidth = false,
}: {
  value: string;
  onChange: (next: string) => void;
  delayMs?: number;
  placeholder?: string;
  ariaLabel?: string;
  className?: string;
  disabled?: boolean;
  fullWidth?: boolean;
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
    <EuiFieldSearch
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      placeholder={placeholder}
      aria-label={ariaLabel}
      disabled={disabled}
      isClearable
      compressed
      fullWidth={fullWidth}
      className={className}
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
    <EuiSelect
      value={String(value)}
      onChange={(e) => onChange(Number(e.target.value))}
      disabled={disabled}
      compressed
      className={className}
      aria-label="Lookback window"
      options={resolvedOptions.map((opt) => ({ value: String(opt.minutes), text: opt.label }))}
    />
  );
}

type StatTone = "default" | "success" | "warning" | "danger" | "info";

function statTitleColor(tone?: StatTone): "default" | "success" | "warning" | "danger" | "primary" {
  switch (tone) {
    case "success":
      return "success";
    case "warning":
      return "warning";
    case "danger":
      return "danger";
    case "info":
      return "primary";
    default:
      return "default";
  }
}

export function DataStatsStrip({
  stats,
  className
}: {
  stats: Array<{ label: string; value: ReactNode; hint?: ReactNode; tone?: StatTone }>;
  className?: string;
}) {
  return (
    <div className={cx("grid gap-2 sm:grid-cols-2 xl:grid-cols-4", className)}>
      {stats.map((item) => (
        <EuiPanel key={item.label} hasBorder hasShadow={false} paddingSize="s" borderRadius="m">
          <EuiStat
            title={item.value}
            description={item.label}
            titleSize="s"
            titleColor={statTitleColor(item.tone)}
          />
          {item.hint ? <div className="mt-1 text-[10px] text-muted-foreground">{item.hint}</div> : null}
        </EuiPanel>
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
  if (tone === "neutral") {
    return (
      <EuiPanel
        color="subdued"
        hasBorder={false}
        hasShadow={false}
        paddingSize="s"
        borderRadius="m"
        role="status"
        aria-live="polite"
      >
        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-muted-foreground">
          <div className="font-mono leading-relaxed">{message}</div>
          {right ? <div className="font-mono">{right}</div> : null}
        </div>
      </EuiPanel>
    );
  }

  return (
    <EuiCallOut color={tone} size="s" role="status">
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
        <div className="font-mono leading-relaxed">{message}</div>
        {right ? <div className="font-mono">{right}</div> : null}
      </div>
    </EuiCallOut>
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
  const cols = Math.max(1, columns);
  return (
    <EuiPanel
      hasBorder
      hasShadow={false}
      paddingSize="none"
      borderRadius="m"
      className={cx("overflow-hidden", className)}
      aria-hidden="true"
    >
      <div className="border-b border-border/60 bg-muted/35 px-3 py-2.5">
        <EuiSkeletonRectangle width="160px" height="12px" borderRadius="s" />
      </div>
      <div className="space-y-2 p-3">
        {Array.from({ length: rows }).map((_, rowIdx) => (
          <div key={rowIdx} className="grid gap-2" style={{ gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))` }}>
            {Array.from({ length: cols }).map((__, colIdx) => (
              <EuiSkeletonRectangle key={colIdx} width="100%" height="16px" borderRadius="s" />
            ))}
          </div>
        ))}
      </div>
    </EuiPanel>
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
    <EuiPanel hasBorder hasShadow={false} paddingSize="none" borderRadius="m" className={className}>
      <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-2.5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="text-[11px] text-muted-foreground">
            Showing <span className="font-semibold text-foreground">{totalCount}</span> rows
          </div>

          <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
            <span className="whitespace-nowrap">Page size</span>
            <EuiSelect
              value={String(pageSize)}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              compressed
              aria-label="Rows per page"
              options={pageSizeOptions.map((value) => ({ value, text: String(value) }))}
            />
          </label>
        </div>

        <div className="flex items-center gap-2">
          {error ? <span className="text-[11px] text-danger">{error}</span> : null}
          {error && onRetry ? (
            <Button variant="secondary" size="sm" onClick={onRetry}>
              Retry
            </Button>
          ) : null}

          {hasMore ? (
            <Button variant="subtle" size="sm" onClick={onLoadMore} disabled={loadingMore || !onLoadMore}>
              {loadingMore ? "Loading..." : loadMoreLabel}
            </Button>
          ) : (
            <span className="text-[11px] text-muted-foreground">No more rows</span>
          )}
        </div>
      </div>
    </EuiPanel>
  );
}
