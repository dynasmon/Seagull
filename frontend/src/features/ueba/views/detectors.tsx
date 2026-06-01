import { useEffect, useMemo, useState, type MouseEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { EuiPanel, EuiStat } from "@elastic/eui";

import { Badge, type BadgeVariant } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import {
  DataPaginationFooter,
  DataQueryStateBanner,
  DataStatsStrip,
  DataTableSkeleton,
} from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { MetricCard } from "@/shared/components/MetricCard";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { StatusPill, type StatusVariant } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { useLiveRefresh } from "@/shared/realtime";

import { listUebaDetectors, listUebaRuns } from "../api";
import type { UebaDetectorRun, UebaDetectorState, UebaDetectorStatus } from "../types";
import {
  detectorDescription,
  detectorLabel,
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

function detectorHealthVariant(status: UebaDetectorStatus | string): StatusVariant {
  switch (status) {
    case "healthy": return "success";
    case "degraded": return "warning";
    case "failing": return "danger";
    default: return "neutral";
  }
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

function MetaRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
        {label}
      </span>
      <span
        className="min-w-0 flex-1 truncate font-mono text-[11px] text-foreground"
        title={typeof value === "string" ? value : undefined}
      >
        {value}
      </span>
    </div>
  );
}

function DetectorCard({
  d,
  onViewFindings,
}: {
  d: UebaDetectorState;
  onViewFindings: (detectorId: string) => void;
}) {
  const meta: Array<{ label: string; value: ReactNode }> = [
    { label: "Last run", value: d.last_run_at ? relativeTime(d.last_run_at) : "—" },
    { label: "Next run", value: d.next_run_at ? relativeTime(d.next_run_at) : "—" },
  ];
  if (d.ml_model_status !== "unavailable") {
    meta.push({
      label: "ML model",
      value: `${d.ml_model_status}${d.ml_model_trained_at ? ` · ${relativeTime(d.ml_model_trained_at)}` : ""}`,
    });
  }
  if (d.last_success_at) {
    meta.push({ label: "Last success", value: relativeTime(d.last_success_at) });
  }
  if (d.last_window_started_at || d.last_window_ended_at) {
    meta.push({
      label: "Last window",
      value: `${d.last_window_started_at ? relativeTime(d.last_window_started_at) : "—"} → ${d.last_window_ended_at ? relativeTime(d.last_window_ended_at) : "—"}`,
    });
  }

  return (
    <EuiPanel hasBorder hasShadow={false} paddingSize="m" borderRadius="m" className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-[13px] font-semibold text-foreground">{detectorLabel(d.detector_id)}</div>
          <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{d.detector_id}</div>
          <div className="mt-1 max-w-prose text-[11px] leading-snug text-muted-foreground">
            {detectorDescription(d.detector_id)}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
          {!d.enabled && <Badge variant="neutral">disabled</Badge>}
          {d.ml_model_status !== "unavailable" && (
            <Badge variant={mlModelStatusVariant(d.ml_model_status)}>ML {d.ml_model_status}</Badge>
          )}
          <StatusPill variant={detectorHealthVariant(d.status)}>{d.status}</StatusPill>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <MetricCard size="sm" title="Baselines" value={d.baseline_count} />
        <MetricCard size="sm" title="Mature" value={d.mature_baseline_count} />
        <EuiPanel
          hasBorder
          hasShadow={false}
          paddingSize="s"
          borderRadius="m"
          className="min-w-0 text-left"
          onClick={() => onViewFindings(d.detector_id)}
          aria-label={`View open anomalies for ${detectorLabel(d.detector_id)}`}
        >
          <EuiStat
            title={d.open_findings}
            description="Open findings"
            titleColor={d.open_findings > 0 ? "warning" : "default"}
            titleSize="s"
            reverse
          />
          <div className="mt-1.5 text-[10px] text-muted-foreground">
            {d.open_findings > 0 ? "View anomalies ↗" : "none open"}
          </div>
        </EuiPanel>
        <MetricCard
          size="sm"
          title="Failures"
          value={d.consecutive_failures}
          tone={d.consecutive_failures > 0 ? "danger" : "default"}
          helper={d.last_error_at ? `last ${relativeTime(d.last_error_at)}` : undefined}
        />
      </div>

      <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-2">
        {meta.map((m) => (
          <MetaRow key={m.label} label={m.label} value={m.value} />
        ))}
      </div>

      {d.error_message && (
        <InlineAlert tone="danger">
          <div className="space-y-0.5">
            {d.error_type && (
              <div className="font-mono text-[10px] uppercase tracking-[0.08em]">{d.error_type}</div>
            )}
            <div className="break-words font-mono text-[11px]">{d.error_message}</div>
          </div>
        </InlineAlert>
      )}
    </EuiPanel>
  );
}

function RunDetail({ run }: { run: UebaDetectorRun }) {
  const contextEntries = Object.entries(run.context).filter(([, value]) => value != null);

  return (
    <div className="w-full bg-muted/10 px-3 py-3">
      <EuiPanel hasBorder hasShadow={false} paddingSize="m" borderRadius="m" className="flex flex-col gap-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
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

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <MetricCard size="sm" title="Events" value={formatCount(run.scanned_events)} />
          <MetricCard size="sm" title="Entities" value={formatCount(run.evaluated_entities)} />
          <MetricCard
            size="sm"
            title="Findings"
            value={run.findings_created > 0 ? `+${formatCount(run.findings_created)}` : "—"}
            tone={run.findings_created > 0 ? "warning" : "default"}
            helper={run.findings_updated > 0 ? `${formatCount(run.findings_updated)} updated` : undefined}
          />
          <MetricCard
            size="sm"
            title="Alerts"
            value={run.alerts_created > 0 ? `+${formatCount(run.alerts_created)}` : "—"}
            tone={run.alerts_created > 0 ? "warning" : "default"}
            helper={run.suppressions_applied > 0 ? `${formatCount(run.suppressions_applied)} suppressed` : undefined}
          />
        </div>

        <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-2">
          <MetaRow
            label="Window"
            value={`${run.window_started_at ? formatTimestamp(run.window_started_at) : "—"} → ${run.window_ended_at ? formatTimestamp(run.window_ended_at) : "—"}`}
          />
          <MetaRow label="Duration" value={formatDuration(run.duration_ms)} />
          <MetaRow
            label="Baselines"
            value={`${formatCount(run.baselines_created)} created · ${formatCount(run.baselines_updated)} updated`}
          />
          <MetaRow label="Version" value={run.detector_version != null ? `v${run.detector_version}` : "—"} />
        </div>

        {run.error_message ? (
          <InlineAlert tone="danger">
            <div className="space-y-0.5">
              <div className="font-mono text-[10px] uppercase tracking-[0.08em]">{run.error_type ?? "run error"}</div>
              <div className="break-words font-mono text-[11px]">{run.error_message}</div>
            </div>
          </InlineAlert>
        ) : null}

        {contextEntries.length > 0 ? (
          <div className="space-y-1.5">
            <div className="font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">Run context</div>
            <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-2">
              {contextEntries.map(([key, value]) => (
                <MetaRow key={key} label={key.replace(/_/g, " ")} value={formatRunValue(value)} />
              ))}
            </div>
          </div>
        ) : null}
      </EuiPanel>
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
      className="!shadow-none !border-0 !bg-transparent !rounded-none"
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

  const summary = useMemo(() => {
    let healthy = 0;
    let degraded = 0;
    let failing = 0;
    let enabled = 0;
    let openFindings = 0;
    let baselines = 0;
    let mature = 0;
    for (const d of detectors) {
      if (d.status === "healthy") healthy += 1;
      if (d.status === "degraded") degraded += 1;
      if (d.status === "failing") failing += 1;
      if (d.enabled) enabled += 1;
      openFindings += d.open_findings;
      baselines += d.baseline_count;
      mature += d.mature_baseline_count;
    }
    return { total: detectors.length, healthy, degraded, failing, enabled, openFindings, baselines, mature };
  }, [detectors]);

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

  const attention = summary.failing + summary.degraded;

  return (
    <div className="space-y-4">
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

      {detectors.length > 0 && (
        <DataStatsStrip
          stats={[
            {
              label: "Detectors",
              value: summary.total,
              hint: `${summary.healthy} healthy · ${summary.enabled} enabled`,
            },
            {
              label: "Needs attention",
              value: attention,
              tone: summary.failing > 0 ? "danger" : summary.degraded > 0 ? "warning" : "default",
              hint: attention > 0 ? `${summary.failing} failing · ${summary.degraded} degraded` : "all operational",
            },
            {
              label: "Open anomalies",
              value: summary.openFindings,
              tone: summary.openFindings > 0 ? "warning" : "default",
              hint: "across detectors",
            },
            {
              label: "Baselines",
              value: summary.baselines,
              hint: `${summary.mature} mature`,
            },
          ]}
        />
      )}

      <Panel
        title="Detectors"
        subtitle={
          !loading ? (
            <span className="font-mono text-[11px] text-muted-foreground">
              {detectors.length} registered
            </span>
          ) : null
        }
      >
        {loading && detectors.length === 0 ? (
          <DataTableSkeleton rows={2} columns={4} />
        ) : detectors.length === 0 ? (
          <EmptyState
            title="No detectors registered"
            description="Detectors will appear here once the anomaly engine registers them."
          />
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
      </Panel>

      <Panel
        title="Recent Runs"
        subtitle={
          !runsLoading ? (
            <span className="font-mono text-[11px] text-muted-foreground">
              {runs.length} run{runs.length !== 1 ? "s" : ""}
              {runsHasMore ? "+" : ""}
            </span>
          ) : null
        }
        actions={
          <div className="w-56">
            <SelectInput
              value={runsDetectorFilter}
              onChange={(e) => setRunsDetectorFilter(e.target.value)}
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
        }
      >
        <div className="space-y-3">
          {runsLoading && runs.length === 0 ? (
            <DataTableSkeleton rows={5} columns={7} />
          ) : runs.length > 0 ? (
            <RunsTable
              runs={runs}
              expandedRunId={expandedRunId}
              onToggleRun={(id) => setExpandedRunId((prev) => (prev === id ? null : id))}
            />
          ) : (
            <EmptyState
              title="No runs recorded yet"
              description="Detector executions will appear here as the anomaly engine runs."
            />
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
      </Panel>
    </div>
  );
}
