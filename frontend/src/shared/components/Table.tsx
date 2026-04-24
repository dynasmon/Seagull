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
  const allRowsSelected = rows.length > 0 && rows.every((row, idx) => selectedSet.has(String(rowKey(row, idx))));
  const anyRowSelected = rows.some((row, idx) => selectedSet.has(String(rowKey(row, idx))));

  const cellPadding = compact ? "px-3 py-1.5" : "px-3 py-2.5";

  return (
    <div
      className={cx("ui-card-shell min-w-0 overflow-hidden", className)}
      role="region"
      aria-label="Data table"
      aria-rowcount={rows.length}
    >
      <div className={cx("min-w-0", scrollX ? "overflow-x-auto overflow-y-hidden" : "overflow-x-hidden")}>
        <table className={cx("min-w-full text-sm", scrollX && "w-max")}>
          <thead
            className={cx(
              stickyHeader && "sticky top-0 z-[2]",
              "bg-surface-2/95 text-left text-[10px] uppercase tracking-[0.08em] text-muted-foreground backdrop-blur-sm"
            )}
          >
            <tr>
              {selectableRows ? (
                <th className="w-10 whitespace-nowrap px-3 py-2.5 align-middle">
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
                    className={cx("whitespace-nowrap font-semibold align-middle", cellPadding, alignClass, c.className || "")}
                    aria-sort={isActiveSort ? (sort?.direction === "asc" ? "ascending" : "descending") : "none"}
                  >
                    {isSortable ? (
                      <button
                        type="button"
                        onClick={() => onSortChange?.({ key, direction: nextDirection(sort, key) })}
                        className={cx(
                          "inline-flex items-center gap-1 rounded-sm px-1 py-0.5",
                          "hover:bg-muted/45 hover:text-foreground",
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
            {(() => {
              const renderKeyCount = new Map<string, number>();
              return rows.map((r, i) => {
                const logicalKey = String(rowKey(r, i));
                const dupCount = renderKeyCount.get(logicalKey) ?? 0;
                renderKeyCount.set(logicalKey, dupCount + 1);
                const renderKey = dupCount === 0 ? logicalKey : `${logicalKey}__dup_${i}`;
                const key = logicalKey;
                const isSelected = (selectedRowKey !== undefined && selectedRowKey !== null && key === selectedRowKey) || selectedSet.has(key);
                const clickable = Boolean(onRowClick);

                return (
                  <tr
                    key={renderKey}
                    className={cx(
                      "border-t border-border/60",
                      clickable ? "cursor-pointer hover:bg-muted/30" : "hover:bg-muted/20",
                      isSelected && "bg-primary/10",
                      rowClassName?.(r, i)
                    )}
                    onClick={() => onRowClick?.(r, i)}
                  >
                    {selectableRows ? (
                      <td className={cx(cellPadding, "align-top")} onClick={(e) => e.stopPropagation()}>
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
                        <td key={c.key} className={cx(cellPadding, "align-top", alignClass, c.className || "")}>
                          {c.render ? c.render(r) : (r as Record<string, unknown>)[c.key] as ReactNode}
                        </td>
                      );
                    })}
                  </tr>
                );
              });
            })()}
          </tbody>
        </table>
      </div>

      {footer ? <div className="border-t border-border/60 bg-muted/20 px-3 py-2">{footer}</div> : null}
    </div>
  );
}
