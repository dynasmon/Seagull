import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import {
  DataPaginationFooter,
  DataQueryStateBanner,
  DataStatsStrip,
  DataTableSkeleton,
  DataViewToolbar,
  DebouncedSearchInput,
} from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import { Panel } from "@/shared/components/Panel";
import { FilterBar, FilterButtonSelect } from "@/shared/components/FilterBar";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { Table, type Column } from "@/shared/components/Table";
import { cx } from "@/shared/lib/cx";
import { useLiveRefresh } from "@/shared/realtime";

import { getUebaSummary, listUebaFindings } from "../api";
import FindingDrawer from "../components/FindingDrawer";
import {
  DETECTOR_LABELS,
  detectorLabel,
  formatMetricValue,
  formatTimestamp,
  metricLabel,
  relativeTime,
  severityVariant,
  verdictLabel,
  verdictVariant,
} from "../components/ueba-utils";
import type { UebaFinding, UebaFindingStatus, UebaSeverity, UebaSummary } from "../types";

const SEVERITY_OPTIONS: Array<{ value: UebaSeverity | "all"; label: string }> = [
  { value: "all", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "informational", label: "Informational" },
];

const STATUS_OPTIONS: Array<{ value: UebaFindingStatus | "all"; label: string }> = [
  { value: "all", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "closed", label: "Closed" },
  { value: "suppressed", label: "Suppressed" },
];

const PAGE_SIZE = 50;

function riskBarClass(score: number): string {
  if (score >= 90) return "bg-severity-critical";
  if (score >= 70) return "bg-severity-high";
  if (score >= 45) return "bg-severity-medium";
  return "bg-severity-low";
}

function SummaryStrip({ summary }: { summary: UebaSummary }) {
  const detectorHealth =
    summary.detectors_failing > 0
      ? `${summary.detectors_failing} failing`
      : summary.detectors_degraded > 0
        ? `${summary.detectors_degraded} degraded`
        : summary.detectors_healthy > 0
          ? "All healthy"
          : "—";

  const healthVariant =
    summary.detectors_failing > 0
      ? "critical"
      : summary.detectors_degraded > 0
        ? "medium"
        : "neutral";

  return (
    <DataStatsStrip
      stats={[
        {
          label: "Open Anomalies",
          value: summary.open_findings,
          hint: summary.high_or_critical_open_findings > 0
            ? `${summary.high_or_critical_open_findings} high or critical`
            : "none high or critical",
        },
        {
          label: "Linked Alerts",
          value: summary.linked_alerts,
          hint: summary.latest_finding_at ? `last: ${relativeTime(summary.latest_finding_at)}` : "none",
        },
        {
          label: "Baselines",
          value: summary.mature_baselines,
          hint: `${summary.warming_baselines} warming, ${summary.stale_baselines} stale`,
        },
        {
          label: "Feedback",
          value: summary.verdicts_last_24h,
          hint: `${(summary.false_positive_rate_7d * 100).toFixed(1)}% FP, ${summary.suppressed_entities} suppressed`,
        },
        {
          label: "Detector Health",
          value: (
            <Badge variant={healthVariant} className="text-xs">
              {detectorHealth}
            </Badge>
          ),
          hint: `${summary.detectors_healthy}/${summary.detectors_total} healthy`,
        },
      ]}
    />
  );
}

type SortKey = "last_seen_at" | "first_seen_at" | "risk_score" | "occurrence_count";
type SortDir = "asc" | "desc";

function sortFindings(
  rows: UebaFinding[],
  key: SortKey,
  dir: SortDir,
): UebaFinding[] {
  const factor = dir === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    let diff = 0;
    if (key === "last_seen_at" || key === "first_seen_at") {
      diff = new Date(a[key]).getTime() - new Date(b[key]).getTime();
    } else {
      diff = (a[key] as number) - (b[key] as number);
    }
    return diff * factor;
  });
}

const FINDING_COLUMNS: Array<Column<UebaFinding>> = [
  {
    key: "risk",
    title: "Risk",
    width: 190,
    sortable: true,
    sortKey: "risk_score",
    render: (row) => (
      <div className="flex flex-nowrap items-center gap-1.5">
        <SeverityPill variant={severityVariant(row.severity)}>
          {row.severity === "informational" ? "info" : row.severity}
        </SeverityPill>
        <Badge variant={row.status === "open" ? "medium" : "neutral"} className="text-[10px]">
          {row.status}
        </Badge>
        {row.latest_verdict && (
          <Badge variant={verdictVariant(row.latest_verdict)} className="text-[10px]">
            {verdictLabel(row.latest_verdict)}
          </Badge>
        )}
        <span className="shrink-0 font-mono text-[10px] text-muted-foreground">risk {row.risk_score}</span>
      </div>
    ),
  },
  {
    key: "entity",
    title: "Entity",
    width: 280,
    render: (row) => (
      <div
        className="flex min-w-0 max-w-[260px] items-center gap-1.5"
        title={`${row.entity_value}\n${row.entity_type}${row.agent_id ? ` · ${row.agent_id}` : ""}`}
      >
        <span className="min-w-0 truncate font-mono text-[12px] font-medium text-foreground">{row.entity_value}</span>
        <span className="min-w-0 max-w-[55%] shrink-0 truncate font-mono text-[10px] text-muted-foreground">
          {row.entity_type}
          {row.agent_id ? ` · ${row.agent_id}` : ""}
        </span>
      </div>
    ),
  },
  {
    key: "detector",
    title: "Detector / Metric",
    width: 240,
    render: (row) => (
      <div className="flex min-w-0 max-w-[220px] items-center gap-1.5">
        <span className="min-w-0 truncate text-[12px] text-foreground" title={detectorLabel(row.detector_id)}>
          {detectorLabel(row.detector_id)}
        </span>
        <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{metricLabel(row.metric_name)}</span>
      </div>
    ),
  },
  {
    key: "observed",
    title: "Observed → Expected",
    width: 260,
    render: (row) => (
      <div className="flex items-center gap-2 whitespace-nowrap font-mono text-[11px]">
        <span className="font-semibold text-foreground">
          {row.observed_value != null ? formatMetricValue(row.observed_value, row.metric_name) : "—"}
        </span>
        {row.expected_value != null && (
          <span className="text-muted-foreground">
            {" → "}
            {formatMetricValue(row.expected_value, row.metric_name)}
          </span>
        )}
        {row.deviation_score != null && (
          <span className="flex items-center gap-1.5">
            <span className="h-1 w-14 shrink-0 overflow-hidden rounded-full bg-muted/40">
              <span
                className={cx("block h-full rounded-full", riskBarClass(row.risk_score))}
                style={{ width: `${Math.min(100, row.risk_score)}%` }}
              />
            </span>
            <span className="text-[10px] text-muted-foreground">z={row.deviation_score.toFixed(1)}</span>
          </span>
        )}
      </div>
    ),
  },
  {
    key: "last_seen",
    title: "Last seen",
    width: 120,
    sortable: true,
    sortKey: "last_seen_at",
    className: "font-mono text-[11px] text-muted-foreground",
    render: (row) => <span title={formatTimestamp(row.last_seen_at)}>{relativeTime(row.last_seen_at)}</span>,
  },
  {
    key: "first_seen",
    title: "First seen",
    width: 120,
    sortable: true,
    sortKey: "first_seen_at",
    className: "font-mono text-[11px] text-muted-foreground",
    render: (row) => <span title={formatTimestamp(row.first_seen_at)}>{relativeTime(row.first_seen_at)}</span>,
  },
  {
    key: "hits",
    title: "Hits",
    width: 80,
    sortable: true,
    sortKey: "occurrence_count",
    align: "right",
    className: "font-mono text-[11px] text-muted-foreground",
    render: (row) => row.occurrence_count,
  },
  {
    key: "mitre",
    title: "MITRE",
    width: 180,
    render: (row) =>
      row.mitre_technique_id ? (
        <div className="flex min-w-0 max-w-[160px] items-center gap-1.5">
          <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{row.mitre_technique_id}</span>
          {row.mitre_tactic ? (
            <span className="min-w-0 truncate text-[10px] text-muted-foreground/70" title={row.mitre_tactic}>
              {row.mitre_tactic.replace(/_/g, " ")}
            </span>
          ) : null}
        </div>
      ) : (
        <span className="text-[10px] text-muted-foreground/40">—</span>
      ),
  },
];

export default function UebaFindingsPage() {
  const [summary, setSummary] = useState<UebaSummary | null>(null);
  const [findings, setFindings] = useState<UebaFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);

  const [searchParams] = useSearchParams();
  const [detectorId, setDetectorId] = useState(searchParams.get("detector_id") ?? "");
  const [agentFilter, setAgentFilter] = useState("");

  const [severity, setSeverity] = useState<UebaSeverity | "all">("all");
  const [status, setStatus] = useState<UebaFindingStatus | "all">("open");
  const [entitySearch, setEntitySearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("last_seen_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const [selectedFinding, setSelectedFinding] = useState<UebaFinding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const reqSeq = useRef(0);
  const abortRef = useRef<AbortController | null>(null);

  const load = useCallback(
    async ({
      replace = true,
      appendCursor,
    }: { replace?: boolean; appendCursor?: string | null } = {}) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      const seq = ++reqSeq.current;

      if (replace) {
        setLoading(true);
        setError(null);
      } else {
        setLoadingMore(true);
      }

      try {
        const [page, sum] = await Promise.all([
          listUebaFindings({
            page_size: PAGE_SIZE,
            cursor: appendCursor ?? null,
            severity: severity !== "all" ? severity : null,
            status: status !== "all" ? status : null,
            entity_value: entitySearch || null,
            detector_id: detectorId || null,
            agent_id: agentFilter || null,
            signal: ctrl.signal,
          }),
          replace
            ? getUebaSummary({ signal: ctrl.signal })
            : Promise.resolve(null),
        ]);

        if (ctrl.signal.aborted || reqSeq.current !== seq) return;

        if (replace) {
          setFindings(page.items);
          if (sum) setSummary(sum);
        } else {
          setFindings((prev) => [...prev, ...page.items]);
        }
        setCursor(page.next_cursor);
        setHasMore(page.has_more);
      } catch (e: unknown) {
        if (ctrl.signal.aborted || reqSeq.current !== seq) return;
        setError((e as Error)?.message ?? "Request failed");
      } finally {
        if (!ctrl.signal.aborted && reqSeq.current === seq) {
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [severity, status, entitySearch, detectorId, agentFilter],
  );

  useEffect(() => {
    load({ replace: true });
    return () => abortRef.current?.abort();
  }, [load]);

  const handleLoadMore = () => {
    if (cursor && !loadingMore) load({ replace: false, appendCursor: cursor });
  };

  useLiveRefresh({ refresh: () => load({ replace: true }) });

  const sorted = sortFindings(findings, sortKey, sortDir);

  return (
    <div className="space-y-4">
      {summary ? <SummaryStrip summary={summary} /> : null}

      <Panel
        title="Anomalies"
        subtitle={
          !loading && !error ? (
            <span className="font-mono text-[11px] text-muted-foreground">
              {findings.length} finding{findings.length !== 1 ? "s" : ""}
              {hasMore ? "+" : ""}
            </span>
          ) : null
        }
      >
        <div className="space-y-3">
          <DataViewToolbar
            left={
              <div className="flex flex-wrap items-center gap-2">
                <FilterBar>
                  <FilterButtonSelect
                    label="Detector"
                    value={detectorId || "all"}
                    options={[
                      { value: "all", label: "All detectors" },
                      ...Object.entries(DETECTOR_LABELS).map(([id, label]) => ({ value: id, label })),
                    ]}
                    onChange={(v) => setDetectorId(v === "all" ? "" : v)}
                    searchable
                  />
                  <FilterButtonSelect
                    label="Severity"
                    value={severity}
                    options={SEVERITY_OPTIONS}
                    onChange={(v) => setSeverity(v as UebaSeverity | "all")}
                  />
                  <FilterButtonSelect
                    label="Status"
                    value={status}
                    options={STATUS_OPTIONS}
                    onChange={(v) => setStatus(v as UebaFindingStatus | "all")}
                  />
                </FilterBar>
                <DebouncedSearchInput
                  value={agentFilter}
                  onChange={setAgentFilter}
                  placeholder="Filter by agent..."
                  className="w-44"
                  ariaLabel="Filter by agent ID"
                />
                <DebouncedSearchInput
                  value={entitySearch}
                  onChange={setEntitySearch}
                  placeholder="Filter by entity..."
                  ariaLabel="Filter by entity value"
                  className="w-56"
                />
              </div>
            }
            right={
              <Button variant="secondary" size="sm" onClick={() => load({ replace: true })} disabled={loading}>
                Refresh
              </Button>
            }
          />

          {error ? (
            <DataQueryStateBanner
              tone="danger"
              message={error}
              right={
                <Button variant="ghost" size="sm" onClick={() => load({ replace: true })}>
                  Retry
                </Button>
              }
            />
          ) : null}

          {loading ? (
            <DataTableSkeleton rows={8} columns={6} />
          ) : sorted.length === 0 ? (
            <EmptyState
              title="No anomalies"
              description="No findings match the current filters. The system will surface anomalies as baselines mature."
            />
          ) : (
            <Table
              className="!shadow-none !border-0 !bg-transparent !rounded-none"
              columns={FINDING_COLUMNS}
              rows={sorted}
              rowKey={(row) => String(row.id)}
              scrollX
              stickyHeader
              selectedRowKey={selectedFinding ? String(selectedFinding.id) : null}
              onRowClick={(row) => {
                setSelectedFinding(row);
                setDrawerOpen(true);
              }}
              sort={{ key: sortKey, direction: sortDir }}
              onSortChange={(next) => {
                setSortKey(next.key as SortKey);
                setSortDir(next.direction);
              }}
            />
          )}

          {!loading && sorted.length > 0 && (
            <DataPaginationFooter
              totalCount={sorted.length}
              pageSize={PAGE_SIZE}
              onPageSizeChange={() => {}}
              pageSizeOptions={[50]}
              hasMore={hasMore}
              loadingMore={loadingMore}
              onLoadMore={handleLoadMore}
            />
          )}
        </div>
      </Panel>

      <FindingDrawer
        open={drawerOpen}
        finding={selectedFinding}
        onClose={() => setDrawerOpen(false)}
        onTriaged={(updated) => {
          setSelectedFinding(updated);
          setFindings((prev) => prev.map((row) => (row.id === updated.id ? updated : row)));
          load({ replace: true });
        }}
      />
    </div>
  );
}
