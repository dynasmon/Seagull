import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";

import { Badge, type BadgeVariant } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { DataPaginationFooter, DataQueryStateBanner, DataTableSkeleton } from "@/shared/components/DataView";
import { SelectInput } from "@/shared/components/SelectInput";
import { Table, type Column } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { useLiveRefresh } from "@/shared/realtime";

import { listUebaDetectors, listUebaRuns } from "../api";
import type { UebaDetectorRun, UebaDetectorState } from "../types";
import {
  detectorDescription,
  detectorLabel,
  detectorStatusVariant,
  formatTimestamp,
  mlModelStatusVariant,
  relativeTime,
} from "../components/ueba-utils";

function RunStatusBadge({ status }: { status: string }) {
  return <Badge variant={runStatusVariant(status)}>{status}</Badge>;
}

function runStatusVariant(status: string): BadgeVariant {
  if (status === "completed") return "low";
  if (status === "running") return "medium";
  return "critical";
}

function outputVariant(value: number): BadgeVariant {
  return value > 0 ? "medium" : "neutral";
}

function formatCount(value: number): string {
  return value.toLocaleString();
}

function formatDuration(ms: number | null): string {
  return ms != null ? `${(ms / 1000).toFixed(1)}s` : "—";
}

function formatRunValue(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "number") return value % 1 === 0 ? formatCount(value) : value.toFixed(3);
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "true" : "false";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function countToneClass(value: number, activeClass = "text-severity-medium") {
  return value > 0 ? activeClass : "text-muted-foreground";
}

function DetectorCard({
  d,
  onViewFindings,
}: {
  d: UebaDetectorState;
  onViewFindings: (detectorId: string) => void;
}) {
  return (
    <div className="rounded-lg border border-border/60 bg-surface-1/60 p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-mono text-[13px] font-semibold text-foreground">
            {detectorLabel(d.detector_id)}
          </div>
          <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{d.detector_id}</div>
          <div className="mt-0.5 text-[11px] text-muted-foreground max-w-xs">
            {detectorDescription(d.detector_id)}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {!d.enabled && <Badge variant="neutral">disabled</Badge>}
          {d.ml_model_status !== "unavailable" && (
            <Badge variant={mlModelStatusVariant(d.ml_model_status)}>
              ML {d.ml_model_status}
            </Badge>
          )}
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
        <button
          type="button"
          onClick={() => onViewFindings(d.detector_id)}
          className="group rounded-md border border-border/40 bg-background/20 px-3 py-2 text-left w-full"
        >
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground group-hover:text-foreground transition-colors">
            Open findings
          </div>
          <div
            className={cx(
              "mt-1 font-mono text-sm font-semibold transition-colors",
              d.open_findings > 0
                ? "text-severity-medium group-hover:text-severity-high"
                : "text-foreground",
            )}
          >
            {d.open_findings}
          </div>
        </button>
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
        {d.ml_model_status !== "unavailable" && (
          <div className="col-span-2 flex items-center justify-between rounded border border-border/40 bg-background/20 px-2.5 py-1.5">
            <span className="text-muted-foreground">ML model</span>
            <span className="text-foreground">
              {d.ml_model_status}
              {d.ml_model_trained_at ? ` · ${relativeTime(d.ml_model_trained_at)}` : ""}
            </span>
          </div>
        )}
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
        {(d.last_window_started_at || d.last_window_ended_at) && (
          <div className="col-span-2 flex items-center justify-between rounded border border-border/40 bg-background/20 px-2.5 py-1.5">
            <span className="font-mono text-[11px] text-muted-foreground">Last window</span>
            <span className="font-mono text-[11px] text-foreground">
              {d.last_window_started_at ? relativeTime(d.last_window_started_at) : "—"}
              {" → "}
              {d.last_window_ended_at ? relativeTime(d.last_window_ended_at) : "—"}
            </span>
          </div>
        )}
      </div>

      {d.error_message && (
        <div className="rounded-md border border-severity-high/30 bg-severity-high/5 px-3 py-2 font-mono text-[11px]">
          {d.error_type && (
            <div className="mb-1 text-[9px] uppercase tracking-widest text-severity-high/60">
              {d.error_type}
            </div>
          )}
          <div className="text-severity-high/90 break-words">{d.error_message}</div>
        </div>
      )}
    </div>
  );
}

function DetailMetric({
  label,
  value,
  hint,
  tone = "text-foreground",
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: string;
}) {
  return (
    <div className="rounded-md border border-border/40 bg-background/20 px-3 py-2">
      <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={cx("mt-1 font-mono text-[13px] font-semibold", tone)}>{value}</div>
      {hint ? <div className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">{hint}</div> : null}
    </div>
  );
}

function DetailLine({
  label,
  children,
  className,
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className="flex min-w-0 items-center justify-between gap-3 rounded border border-border/40 bg-background/20 px-2.5 py-1.5">
      <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
        {label}
      </span>
      <span className={cx("min-w-0 truncate font-mono text-[11px] text-foreground", className)}>
        {children}
      </span>
    </div>
  );
}

function RunDetail({ run }: { run: UebaDetectorRun }) {
  const contextEntries = Object.entries(run.context).filter(([, value]) => value != null);

  return (
    <div className="w-full bg-muted/10 px-3 py-3">
      <div className="w-full rounded-md border border-border/50 bg-surface-1/70 p-3 shadow-sm">
        <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-1.5">
              <span className="truncate text-[12px] font-medium text-foreground" title={detectorLabel(run.detector_id)}>
                {detectorLabel(run.detector_id)}
              </span>
              <span className="shrink-0 font-mono text-[10px] text-muted-foreground">run #{run.id}</span>
            </div>
            <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">
              {formatTimestamp(run.started_at)}
              {run.finished_at ? ` → ${formatTimestamp(run.finished_at)}` : ""}
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-1.5">
            <RunStatusBadge status={run.status} />
            <Badge variant={outputVariant(run.findings_created)} className="text-[10px]">
              {run.findings_created > 0 ? `+${formatCount(run.findings_created)} findings` : "no findings"}
            </Badge>
            <Badge variant={outputVariant(run.alerts_created)} className="text-[10px]">
              {run.alerts_created > 0 ? `+${formatCount(run.alerts_created)} alerts` : "no alerts"}
            </Badge>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-4">
          <DetailMetric label="Events" value={formatCount(run.scanned_events)} />
          <DetailMetric label="Entities" value={formatCount(run.evaluated_entities)} />
          <DetailMetric
            label="Findings"
            value={run.findings_created > 0 ? `+${formatCount(run.findings_created)}` : "—"}
            hint={run.findings_updated > 0 ? `${formatCount(run.findings_updated)} updated` : undefined}
            tone={countToneClass(run.findings_created)}
          />
          <DetailMetric
            label="Alerts"
            value={run.alerts_created > 0 ? `+${formatCount(run.alerts_created)}` : "—"}
            hint={run.suppressions_applied > 0 ? `${formatCount(run.suppressions_applied)} suppressed` : undefined}
            tone={countToneClass(run.alerts_created)}
          />
        </div>

        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          <DetailLine label="Window">
            {run.window_started_at ? formatTimestamp(run.window_started_at) : "—"}
            {" → "}
            {run.window_ended_at ? formatTimestamp(run.window_ended_at) : "—"}
          </DetailLine>
          <DetailLine label="Duration">{formatDuration(run.duration_ms)}</DetailLine>
          <DetailLine label="Baselines">
            {formatCount(run.baselines_created)} created
            {" · "}
            {formatCount(run.baselines_updated)} updated
          </DetailLine>
          <DetailLine label="Version">
            {run.detector_version != null ? `v${run.detector_version}` : "—"}
          </DetailLine>
        </div>

        {run.error_message ? (
          <div className="mt-3 rounded-md border border-severity-high/35 bg-severity-high/5 px-3 py-2">
            <div className="mb-1 flex items-center gap-2">
              <Badge variant="critical" className="text-[10px]">
                {run.error_type ?? "run error"}
              </Badge>
              <span className="font-mono text-[10px] uppercase tracking-widest text-severity-high/70">
                Detector failure
              </span>
            </div>
            <div className="break-words font-mono text-[11px] text-severity-high">
              {run.error_message}
            </div>
          </div>
        ) : null}

        {contextEntries.length > 0 ? (
          <div className="mt-3">
            <div className="mb-1.5 font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
              Run context
            </div>
            <div className="grid gap-1.5 sm:grid-cols-2">
              {contextEntries.map(([key, value]) => (
                <DetailLine key={key} label={key.replace(/_/g, " ")}>
                  {formatRunValue(value)}
                </DetailLine>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

const RUN_COLUMNS: Array<Column<UebaDetectorRun>> = [
  {
    key: "detector",
    title: "Detector / Run",
    width: 240,
    render: (run) => (
      <div className="flex min-w-0 max-w-[220px] items-center gap-1.5">
        <span className="min-w-0 truncate text-[12px] text-foreground" title={detectorLabel(run.detector_id)}>
          {detectorLabel(run.detector_id)}
        </span>
        <span className="shrink-0 font-mono text-[10px] text-muted-foreground">#{run.id}</span>
        {run.detector_version != null ? (
          <span className="shrink-0 font-mono text-[10px] text-muted-foreground/70">v{run.detector_version}</span>
        ) : null}
      </div>
    ),
  },
  {
    key: "status",
    title: "Status",
    width: 130,
    render: (run) => (
      <div className="flex flex-nowrap items-center gap-1.5">
        <RunStatusBadge status={run.status} />
        {run.error_type ? (
          <Badge variant="critical" className="text-[10px]">
            {run.error_type}
          </Badge>
        ) : null}
      </div>
    ),
  },
  {
    key: "work",
    title: "Workload",
    width: 200,
    render: (run) => (
      <div className="flex items-center gap-2 whitespace-nowrap font-mono text-[11px]">
        <span className="font-semibold text-foreground">{formatCount(run.scanned_events)}</span>
        <span className="text-muted-foreground">events</span>
        <span className="text-muted-foreground/50">·</span>
        <span className="font-semibold text-foreground">{formatCount(run.evaluated_entities)}</span>
        <span className="text-muted-foreground">entities</span>
      </div>
    ),
  },
  {
    key: "output",
    title: "Output",
    width: 215,
    render: (run) => (
      <div className="flex flex-nowrap items-center gap-1.5">
        <Badge variant={outputVariant(run.findings_created)} className="text-[10px]">
          {run.findings_created > 0 ? `+${formatCount(run.findings_created)} findings` : "no findings"}
        </Badge>
        {run.findings_updated > 0 ? (
          <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
            {formatCount(run.findings_updated)} updated
          </span>
        ) : null}
        {run.alerts_created > 0 ? (
          <Badge variant="medium" className="text-[10px]">
            +{formatCount(run.alerts_created)} alerts
          </Badge>
        ) : null}
      </div>
    ),
  },
  {
    key: "baselines",
    title: "Baselines",
    width: 145,
    render: (run) => (
      <div className="flex items-center gap-1.5 whitespace-nowrap font-mono text-[11px]">
        <span className={countToneClass(run.baselines_created, "text-severity-low")}>
          {run.baselines_created > 0 ? `+${formatCount(run.baselines_created)}` : "—"}
        </span>
        <span className="text-muted-foreground">created</span>
        <span className="text-muted-foreground/50">·</span>
        <span className={countToneClass(run.baselines_updated, "text-foreground")}>
          {formatCount(run.baselines_updated)}
        </span>
        <span className="text-muted-foreground">updated</span>
      </div>
    ),
  },
  {
    key: "duration",
    title: "Duration",
    align: "right",
    width: 90,
    className: "font-mono text-muted-foreground",
    render: (run) => formatDuration(run.duration_ms),
  },
  {
    key: "started",
    title: "Started",
    align: "right",
    width: 120,
    className: "font-mono text-[11px] text-muted-foreground",
    render: (run) => <span title={formatTimestamp(run.started_at)}>{relativeTime(run.started_at)}</span>,
  },
];

function restoreRunRowPosition(runId: number, row: HTMLElement | null, beforeTop: number) {
  window.requestAnimationFrame(() => {
    window.requestAnimationFrame(() => {
      const nextRow = document.querySelector<HTMLElement>(`[data-seagull-row-key="${runId}"]`);
      const anchor = nextRow ?? row;
      if (!anchor) return;
      const delta = anchor.getBoundingClientRect().top - beforeTop;
      if (Math.abs(delta) > 1) {
        const scroller = findScrollParent(anchor);
        if (scroller) {
          scroller.scrollTop += delta;
        } else {
          window.scrollTo({ top: window.scrollY + delta, left: window.scrollX, behavior: "auto" });
        }
      }
    });
  });
}

function findScrollParent(element: HTMLElement): HTMLElement | null {
  let node = element.parentElement;
  while (node) {
    const style = window.getComputedStyle(node);
    if (
      /(auto|scroll|overlay)/.test(`${style.overflowY} ${style.overflow}`) &&
      node.scrollHeight > node.clientHeight
    ) {
      return node;
    }
    node = node.parentElement;
  }
  return null;
}

function RunsTable({
  runs,
  expandedRunId,
  onToggleRun,
}: {
  runs: UebaDetectorRun[];
  expandedRunId: number | null;
  onToggleRun: (id: number) => void;
}) {
  if (runs.length === 0) return null;

  const expandedRun = expandedRunId == null ? null : runs.find((run) => run.id === expandedRunId);
  const expandedRowMap = expandedRun
    ? { [String(expandedRun.id)]: <RunDetail run={expandedRun} /> }
    : undefined;

  return (
    <Table
      columns={RUN_COLUMNS}
      rows={runs}
      rowKey={(run) => String(run.id)}
      scrollX
      stickyHeader
      selectedRowKey={expandedRunId == null ? null : String(expandedRunId)}
      onRowClick={(run, _idx, event: MouseEvent<HTMLTableRowElement>) => {
        const row = event.currentTarget;
        const beforeTop = row.getBoundingClientRect().top;
        onToggleRun(run.id);
        restoreRunRowPosition(run.id, row, beforeTop);
      }}
      expandedRowMap={expandedRowMap}
    />
  );
}

export default function DetectorsView() {
  const [detectors, setDetectors] = useState<UebaDetectorState[]>([]);
  const [runs, setRuns] = useState<UebaDetectorRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedRunId, setExpandedRunId] = useState<number | null>(null);
  const [runsDetectorFilter, setRunsDetectorFilter] = useState("");
  const [runsCursor, setRunsCursor] = useState<string | null>(null);
  const [runsHasMore, setRunsHasMore] = useState(false);
  const [runsLoadingMore, setRunsLoadingMore] = useState(false);
  const [runsLoading, setRunsLoading] = useState(true);

  const navigate = useNavigate();

  const load = (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);
    listUebaDetectors({ signal })
      .then((ds) => {
        if (signal?.aborted) return;
        setDetectors(ds);
        setLoading(false);
      })
      .catch((e: unknown) => {
        if (signal?.aborted) return;
        setError((e as Error)?.message ?? "Failed to load detectors");
        setLoading(false);
      });
  };

  const loadRuns = async (
    detectorId: string,
    opts: { replace?: boolean; appendCursor?: string | null } = {},
  ) => {
    const { replace = true, appendCursor } = opts;
    if (replace) {
      setRunsLoading(true);
    } else {
      setRunsLoadingMore(true);
    }
    try {
      const page = await listUebaRuns({
        page_size: 50,
        detector_id: detectorId || null,
        cursor: appendCursor ?? null,
      });
      if (replace) {
        setRuns(page.items);
      } else {
        setRuns((prev) => [...prev, ...page.items]);
      }
      setRunsCursor(page.next_cursor);
      setRunsHasMore(page.has_more);
    } catch {
      // no-op
    } finally {
      if (replace) setRunsLoading(false);
      setRunsLoadingMore(false);
    }
  };

  useEffect(() => {
    const ctrl = new AbortController();
    load(ctrl.signal);
    return () => ctrl.abort();
  }, []);

  useEffect(() => {
    loadRuns(runsDetectorFilter);
  }, [runsDetectorFilter]);

  useLiveRefresh({ refresh: () => load() });

  return (
    <div className="space-y-6">
      {error && (
        <DataQueryStateBanner
          message={error}
          tone="danger"
          right={
            <Button variant="ghost" size="sm" onClick={() => load()}>
              Retry
            </Button>
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
              <DetectorCard
                key={d.detector_id}
                d={d}
                onViewFindings={(id) => navigate(`/ueba/findings?detector_id=${encodeURIComponent(id)}`)}
              />
            ))}
          </div>
        )}
      </div>

      <div>
        <div className="flex items-center gap-3 mb-3">
          <h3 className="font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            Recent Runs
          </h3>
          <div className="ml-auto w-56">
            <SelectInput
              value={runsDetectorFilter}
              onChange={(e) => setRunsDetectorFilter(e.target.value)}
              className="text-xs font-mono"
              aria-label="Filter runs by detector"
            >
              <option value="">All detectors</option>
              {detectors.map((d) => (
                <option key={d.detector_id} value={d.detector_id}>
                  {detectorLabel(d.detector_id)}
                </option>
              ))}
            </SelectInput>
          </div>
        </div>
        {runsLoading && runs.length === 0 ? (
          <DataTableSkeleton rows={5} columns={7} />
        ) : runs.length > 0 ? (
          <RunsTable
            runs={runs}
            expandedRunId={expandedRunId}
            onToggleRun={(id) => setExpandedRunId((prev) => (prev === id ? null : id))}
          />
        ) : (
          <div className="rounded-lg border border-border/60 bg-muted/10 px-4 py-8 text-center font-mono text-[12px] text-muted-foreground">
            No runs recorded yet.
          </div>
        )}
        {!runsLoading && runs.length > 0 && (
          <DataPaginationFooter
            totalCount={runs.length}
            pageSize={50}
            onPageSizeChange={() => {}}
            pageSizeOptions={[50]}
            hasMore={runsHasMore}
            loadingMore={runsLoadingMore}
            onLoadMore={() => {
              if (runsCursor && !runsLoadingMore) {
                loadRuns(runsDetectorFilter, { replace: false, appendCursor: runsCursor });
              }
            }}
          />
        )}
      </div>
    </div>
  );
}
