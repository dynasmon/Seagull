import { Badge } from "@/shared/components/Badge";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";

import type { ResponseActionResultOut } from "../types";
import { DryRunBadge } from "./lib";

type KilledRow = {
  pid?: number;
  name?: string;
  signal?: string;
  ok?: boolean;
  error?: string;
};

export default function KillProcessResultRenderer({ result }: { result: ResponseActionResultOut }) {
  const payload = result.result_payload || {};
  const dryRun = Boolean(payload.dry_run);
  const killed: KilledRow[] = Array.isArray(payload.killed) ? payload.killed : [];
  const matched = typeof payload.matched === "number" ? payload.matched : killed.length;
  const signal = String(payload.signal || "SIGTERM");
  const errors: string[] = Array.isArray(payload.errors) ? payload.errors : [];
  const failedCount = killed.filter((row) => row.ok === false).length;

  const columns: Array<Column<KilledRow>> = [
    { key: "pid", title: "PID", width: 90, render: (row) => <span className="font-mono text-[11px]">{row.pid ?? "—"}</span> },
    { key: "name", title: "Name", render: (row) => <span className="font-mono text-[11px]">{row.name || "—"}</span> },
    { key: "signal", title: "Signal", width: 110, render: (row) => <span className="font-mono text-[11px]">{row.signal || signal}</span> },
    {
      key: "result",
      title: "Result",
      render: (row) =>
        row.ok === false ? (
          <span className="flex items-center gap-2">
            <StatusPill variant="danger">failed</StatusPill>
            {row.error ? (
              <span className="truncate text-[11px] text-muted-foreground" title={row.error}>
                {row.error}
              </span>
            ) : null}
          </span>
        ) : (
          <StatusPill variant="success">{dryRun ? "would signal" : "signalled"}</StatusPill>
        ),
    },
  ];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[13px] font-semibold text-foreground">
          {matched} process{matched === 1 ? "" : "es"} {dryRun ? "matched" : "signalled"}
        </span>
        <Badge variant="neutral">{signal}</Badge>
        {dryRun ? <DryRunBadge /> : null}
        {failedCount > 0 ? <Badge variant="high">{failedCount} failed</Badge> : null}
      </div>

      {errors.length > 0 && !dryRun ? <InlineAlert tone="danger">{errors.join(" · ")}</InlineAlert> : null}

      {killed.length === 0 ? (
        <EmptyState title="No matching processes" hint="The target did not match any running process." />
      ) : (
        <Table<KilledRow> columns={columns} rows={killed} rowKey={(row, idx) => String(row.pid ?? idx)} compact />
      )}
    </div>
  );
}
