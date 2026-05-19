import { useEffect, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import { DataQueryStateBanner, DataTableSkeleton } from "@/shared/components/DataView";
import { useLiveRefresh } from "@/shared/realtime";

import { listUebaDetectors, listUebaRuns } from "../api";
import type { UebaDetectorRun, UebaDetectorState } from "../types";
import { detectorLabel, detectorStatusVariant, formatTimestamp, relativeTime } from "../components/ueba-utils";

function RunStatusBadge({ status }: { status: string }) {
  const v =
    status === "completed" ? "low"
    : status === "running" ? "medium"
    : "critical";
  return <Badge variant={v}>{status}</Badge>;
}

function DetectorCard({ d }: { d: UebaDetectorState }) {
  return (
    <div className="rounded-lg border border-border/60 bg-surface-1/60 p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-mono text-[13px] font-semibold text-foreground">
            {detectorLabel(d.detector_id)}
          </div>
          <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{d.detector_id}</div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {!d.enabled && <Badge variant="neutral">disabled</Badge>}
          <Badge variant={detectorStatusVariant(d.status)}>{d.status}</Badge>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <div className="rounded-md border border-border/40 bg-background/20 px-3 py-2">
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">Baselines</div>
          <div className="mt-1 font-mono text-sm font-semibold text-foreground">{d.baseline_count}</div>
        </div>
        <div className="rounded-md border border-border/40 bg-background/20 px-3 py-2">
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">Mature</div>
          <div className="mt-1 font-mono text-sm text-foreground">{d.mature_baseline_count}</div>
        </div>
        <div className="rounded-md border border-border/40 bg-background/20 px-3 py-2">
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">Open findings</div>
          <div className="mt-1 font-mono text-sm text-foreground">{d.open_findings}</div>
        </div>
        <div className="rounded-md border border-border/40 bg-background/20 px-3 py-2">
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">Failures</div>
          <div className={`mt-1 font-mono text-sm ${d.consecutive_failures > 0 ? "text-severity-high" : "text-foreground"}`}>
            {d.consecutive_failures}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
        <div className="flex items-center justify-between rounded border border-border/40 bg-background/20 px-2.5 py-1.5">
          <span className="text-muted-foreground">Last run</span>
          <span className="text-foreground">{d.last_run_at ? relativeTime(d.last_run_at) : "—"}</span>
        </div>
        <div className="flex items-center justify-between rounded border border-border/40 bg-background/20 px-2.5 py-1.5">
          <span className="text-muted-foreground">Next run</span>
          <span className="text-foreground">{d.next_run_at ? relativeTime(d.next_run_at) : "—"}</span>
        </div>
        {d.last_success_at && (
          <div className="flex items-center justify-between rounded border border-border/40 bg-background/20 px-2.5 py-1.5">
            <span className="text-muted-foreground">Last success</span>
            <span className="text-foreground">{relativeTime(d.last_success_at)}</span>
          </div>
        )}
        {d.last_error_at && (
          <div className="flex items-center justify-between rounded border border-border/40 bg-background/20 px-2.5 py-1.5">
            <span className="text-muted-foreground">Last error</span>
            <span className="text-severity-high">{relativeTime(d.last_error_at)}</span>
          </div>
        )}
      </div>

      {d.error_message && (
        <div className="rounded-md border border-severity-high/30 bg-severity-high/5 px-3 py-2 font-mono text-[11px]">
          <div className="mb-1 text-[9px] uppercase tracking-widest text-severity-high/80">Last error</div>
          <div className="text-severity-high/90 break-words">{d.error_message}</div>
        </div>
      )}
    </div>
  );
}

function RunsTable({ runs }: { runs: UebaDetectorRun[] }) {
  if (runs.length === 0) return null;
  return (
    <div className="overflow-x-auto rounded-lg border border-border/60">
      <table className="w-full min-w-[700px] text-[12px]">
        <thead>
          <tr className="border-b border-border/60 bg-muted/30">
            <th className="px-3 py-2 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Detector</th>
            <th className="px-3 py-2 text-left font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Status</th>
            <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Events</th>
            <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Entities</th>
            <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Findings</th>
            <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Duration</th>
            <th className="px-3 py-2 text-right font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Started</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.id} className="border-b border-border/40 hover:bg-muted/20">
              <td className="px-3 py-2 font-mono text-foreground">{detectorLabel(r.detector_id)}</td>
              <td className="px-3 py-2">
                <RunStatusBadge status={r.status} />
              </td>
              <td className="px-3 py-2 text-right font-mono text-muted-foreground">{r.scanned_events.toLocaleString()}</td>
              <td className="px-3 py-2 text-right font-mono text-muted-foreground">{r.evaluated_entities}</td>
              <td className="px-3 py-2 text-right font-mono">
                <span className={r.findings_created > 0 ? "text-severity-medium" : "text-muted-foreground"}>
                  {r.findings_created > 0 ? `+${r.findings_created}` : "—"}
                </span>
              </td>
              <td className="px-3 py-2 text-right font-mono text-muted-foreground">
                {r.duration_ms != null ? `${(r.duration_ms / 1000).toFixed(1)}s` : "—"}
              </td>
              <td className="px-3 py-2 text-right font-mono text-muted-foreground">{formatTimestamp(r.started_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function DetectorsView() {
  const [detectors, setDetectors] = useState<UebaDetectorState[]>([]);
  const [runs, setRuns] = useState<UebaDetectorRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);
    Promise.all([
      listUebaDetectors({ signal }),
      listUebaRuns({ page_size: 20, signal }),
    ])
      .then(([ds, rs]) => {
        if (signal?.aborted) return;
        setDetectors(ds);
        setRuns(rs.items);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (signal?.aborted) return;
        setError((e as Error)?.message ?? "Failed to load detectors");
        setLoading(false);
      });
  };

  useEffect(() => {
    const ctrl = new AbortController();
    load(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  useLiveRefresh({ refresh: () => load() });

  return (
    <div className="space-y-6">
      {error && (
        <DataQueryStateBanner
          message={error}
          tone="danger"
          right={
            <button type="button" className="underline" onClick={() => load()}>
              Retry
            </button>
          }
        />
      )}

      <div>
        <h3 className="mb-3 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Detector Status</h3>
        {loading && detectors.length === 0 ? (
          <DataTableSkeleton rows={2} columns={4} />
        ) : detectors.length === 0 ? (
          <div className="rounded-lg border border-border/60 bg-muted/10 px-4 py-8 text-center font-mono text-[12px] text-muted-foreground">
            No detectors registered.
          </div>
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            {detectors.map((d) => (
              <DetectorCard key={d.detector_id} d={d} />
            ))}
          </div>
        )}
      </div>

      <div>
        <h3 className="mb-3 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">Recent Runs</h3>
        {loading && runs.length === 0 ? (
          <DataTableSkeleton rows={5} columns={7} />
        ) : (
          <RunsTable runs={runs} />
        )}
        {!loading && runs.length === 0 && (
          <div className="rounded-lg border border-border/60 bg-muted/10 px-4 py-8 text-center font-mono text-[12px] text-muted-foreground">
            No runs recorded yet.
          </div>
        )}
      </div>
    </div>
  );
}
