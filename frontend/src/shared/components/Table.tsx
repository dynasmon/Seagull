import type { ReactNode } from "react";

import { cx } from "@/shared/lib/cx";

export type TableSortState = {
  key: string;
  direction: "asc" | "desc";
};

export type Column<T> = {
  key: string;
  title: string;
  render?: (row: T) => ReactNode;
  className?: string;
  width?: number;
  sortable?: boolean;
  sortKey?: string;
  align?: "left" | "center" | "right";
};

function toSelectedSet(input?: string[] | Set<string>): Set<string> {
  if (!input) return new Set();
  if (input instanceof Set) return input;
  return new Set(input);
}

function nextDirection(current: TableSortState | null | undefined, key: string): "asc" | "desc" {
  if (!current || current.key !== key) return "asc";
  return current.direction === "asc" ? "desc" : "asc";
}

export function Table<T>({
  columns,
  rows,
  rowKey,
  className,
  scrollX = true,
  stickyHeader = true,
  compact = false,
  selectedRowKey,
  selectedRowKeys,
  selectableRows = false,
  onToggleRow,
  onToggleAllRows,
  onRowClick,
  sort,
  onSortChange,
  rowClassName,
  footer
}: {
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T, idx: number) => string;
  className?: string;
  /** Enable horizontal scrolling when the table content is wider than its container. */
  scrollX?: boolean;
  stickyHeader?: boolean;
  compact?: boolean;
  selectedRowKey?: string | null;
  selectedRowKeys?: string[] | Set<string>;
  selectableRows?: boolean;
  onToggleRow?: (row: T, checked: boolean) => void;
  onToggleAllRows?: (checked: boolean) => void;
  onRowClick?: (row: T, idx: number) => void;
  sort?: TableSortState | null;
  onSortChange?: (next: TableSortState) => void;
  rowClassName?: (row: T, idx: number) => string | undefined;
  footer?: ReactNode;
}) {
  const selectedSet = toSelectedSet(selectedRowKeys);
  const allRowsSelected = rows.length > 0 && rows.every((row, idx) => selectedSet.has(rowKey(row, idx)));
  const anyRowSelected = rows.some((row, idx) => selectedSet.has(rowKey(row, idx)));

  const cellPadding = compact ? "px-3 py-1.5" : "px-3 py-2.5";

  return (
    <div
      className={cx("ui-card-shell overflow-y-auto", scrollX ? "overflow-x-auto" : "overflow-x-hidden")}
      role="region"
      aria-label="Data table"
    >
      <table className={cx("w-full", className || "text-sm")}>
        <thead className={cx(stickyHeader && "sticky top-0 z-[1]", "bg-muted/60 text-left text-[11px] text-muted-foreground uppercase tracking-[0.08em]")}>
          <tr>
            {selectableRows ? (
              <th className="w-10 px-3 py-2.5">
                <input
                  type="checkbox"
                  checked={allRowsSelected}
                  ref={(el) => {
                    if (!el) return;
                    el.indeterminate = !allRowsSelected && anyRowSelected;
                  }}
                  onChange={(e) => onToggleAllRows?.(e.target.checked)}
                  aria-label="Select all rows"
                  className="h-4 w-4"
                />
              </th>
            ) : null}

            {columns.map((c) => {
              const key = c.sortKey || c.key;
              const isSortable = Boolean(c.sortable && onSortChange);
              const isActiveSort = Boolean(sort && sort.key === key);
              const alignClass = c.align === "right" ? "text-right" : c.align === "center" ? "text-center" : "text-left";

              return (
                <th
                  key={c.key}
                  style={c.width ? { width: c.width } : undefined}
                  className={cx("font-semibold", cellPadding, alignClass, c.className || "")}
                  aria-sort={isActiveSort ? (sort?.direction === "asc" ? "ascending" : "descending") : "none"}
                >
                  {isSortable ? (
                    <button
                      type="button"
                      onClick={() => onSortChange?.({ key, direction: nextDirection(sort, key) })}
                      className={cx(
                        "inline-flex items-center gap-1 rounded-sm px-1 py-0.5",
                        "hover:bg-muted/70 hover:text-foreground",
                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/35"
                      )}
                    >
                      <span>{c.title}</span>
                      <span aria-hidden="true" className={cx("text-[10px]", isActiveSort ? "text-foreground" : "text-muted-foreground/70")}>
                        {isActiveSort ? (sort?.direction === "asc" ? "▲" : "▼") : "↕"}
                      </span>
                    </button>
                  ) : (
                    c.title
                  )}
                </th>
              );
            })}
          </tr>
        </thead>

        <tbody>
          {rows.map((r, i) => {
            const key = rowKey(r, i);
            const isSelected = (selectedRowKey !== undefined && selectedRowKey !== null && key === selectedRowKey) || selectedSet.has(key);
            const clickable = Boolean(onRowClick);

            return (
              <tr
                key={key}
                className={cx(
                  "border-t border-border/50",
                  clickable ? "cursor-pointer hover:bg-muted/45" : "hover:bg-muted/35",
                  isSelected && "bg-muted/50",
                  rowClassName?.(r, i)
                )}
                onClick={() => onRowClick?.(r, i)}
              >
                {selectableRows ? (
                  <td className={cellPadding} onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedSet.has(key)}
                      onChange={(e) => onToggleRow?.(r, e.target.checked)}
                      aria-label={`Select row ${i + 1}`}
                      className="h-4 w-4"
                    />
                  </td>
                ) : null}

                {columns.map((c) => {
                  const alignClass = c.align === "right" ? "text-right" : c.align === "center" ? "text-center" : "text-left";
                  return (
                    <td key={c.key} className={cx(cellPadding, alignClass, c.className || "")}>
                      {c.render ? c.render(r) : (r as Record<string, unknown>)[c.key] as ReactNode}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>

      {footer ? <div className="border-t border-border/60 bg-muted/20 px-3 py-2">{footer}</div> : null}
    </div>
  );
}
