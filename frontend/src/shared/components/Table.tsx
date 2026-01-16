import React from "react";

export type Column<T> = {
  key: string;
  title: string;
  render?: (row: T) => React.ReactNode;
  className?: string;
};

export function Table<T>({
  columns,
  rows,
  rowKey
}: {
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T, idx: number) => string;
}) {
  return (
    <div className="overflow-auto rounded-md border border-[var(--border)]">
      <table className="w-full text-sm">
        <thead className="bg-[var(--panel2)] text-left text-xs text-[var(--muted)]">
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={`px-3 py-2 font-semibold ${c.className || ""}`}>
                {c.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={rowKey(r, i)} className="border-t border-[var(--border)]">
              {columns.map((c) => (
                <td key={c.key} className={`px-3 py-2 ${c.className || ""}`}>
                  {c.render ? c.render(r) : (r as any)[c.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
