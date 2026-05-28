import { Button } from "@/shared/components/Button";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { cx } from "@/shared/lib/cx";

import type { Density } from "../constants";
import { fmtTs } from "../lib/alertFormatters";
import { alertIpContext } from "../lib/alertPresenters";
import { sevVariant } from "../lib/alertSeverity";
import type { Alert } from "../types";

interface AlertsTableProps {
  rows: Alert[];
  selectedId: number | null;
  onEdit: (a: Alert) => void;
  selectedRowIds: Set<number>;
  onToggleRow: (alertId: number, nextChecked: boolean) => void;
  onToggleAllRows: (nextChecked: boolean) => void;
  density?: Density;
}

export function AlertsTable({
  rows,
  selectedId,
  onEdit,
  selectedRowIds,
  onToggleRow,
  onToggleAllRows,
  density,
}: AlertsTableProps) {
  const dense = density === "compact";
  const allVisibleSelected = rows.length > 0 && rows.every((row) => selectedRowIds.has(row.id));
  const cellPad = dense ? "py-1.5" : "py-2.5";

  return (
    <div className="w-full">
      <table className="w-full text-sm">
        <thead className="sticky top-0 z-10 bg-surface-2/95 backdrop-blur-sm">
          <tr className="text-left text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
            <th className={cx("w-10 border-b border-border px-3", cellPad)}>
              <input
                type="checkbox"
                checked={allVisibleSelected}
                onChange={(e) => onToggleAllRows(e.target.checked)}
                aria-label="Select visible alerts"
                className="h-3.5 w-3.5 cursor-pointer accent-primary"
              />
            </th>
            <th className={cx("border-b border-border px-3 font-semibold", cellPad)}>Alert</th>
            <th className={cx("border-b border-border px-3 font-semibold", cellPad)}>Network</th>
            <th className={cx("border-b border-border px-3 font-semibold", cellPad)}>Description</th>
            <th className={cx("border-b border-border px-3 text-right font-semibold", cellPad)}>Actions</th>
          </tr>
        </thead>

        <tbody>
          {rows.map((a) => {
            const selected = selectedId !== null && a.id === selectedId;
            return (
              <tr
                key={a.id}
                className={cx(
                  "cursor-pointer border-t border-border/55 ui-row",
                  selected && "ui-row-selected",
                )}
                role="button"
                tabIndex={0}
                onClick={() => onEdit(a)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onEdit(a);
                  }
                }}
              >
                <td className={cx("px-3", cellPad)} onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={selectedRowIds.has(a.id)}
                    onChange={(e) => onToggleRow(a.id, e.target.checked)}
                    aria-label={`Select alert ${a.id}`}
                    className="h-3.5 w-3.5 cursor-pointer accent-primary"
                  />
                </td>

                <td className={cx("px-3", cellPad)}>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <SeverityPill variant={sevVariant(String(a.severity || "unknown"))} withDot>
                      {String(a.severity || "unknown")}
                    </SeverityPill>
                    <span className="break-all font-mono text-[12px] text-foreground">{a.rule_id}</span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">{fmtTs(a.created_at)}</div>
                </td>

                <td className={cx("px-3 text-[12px]", cellPad)}>
                  <div>
                    <IpAddressPill ip={a.src_ip} ipContext={alertIpContext(a, "src")} compact />
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
                      <IpAddressPill ip={a.dst_ip} ipContext={alertIpContext(a, "dst")} compact />
                      {typeof a.dst_port === "number" ? <span>:{a.dst_port}</span> : null}
                    </span>
                  </div>
                </td>

                <td className={cx("px-3", cellPad)}>
                  <div className="line-clamp-2 text-[12px] text-muted-foreground">{a.description || ""}</div>
                </td>

                <td className={cx("px-3 text-right", cellPad)}>
                  <Button
                    variant="subtle"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      onEdit(a);
                    }}
                    title="Open drawer"
                  >
                    View
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
