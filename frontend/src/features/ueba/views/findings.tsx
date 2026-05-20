import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
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
import { SeverityPill } from "@/shared/components/SeverityPill";
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

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  const SortHeader = ({
    col,
    children,
    className,
  }: {
    col: SortKey;
    children: React.ReactNode;
    className?: string;
  }) => (
    <button
      type="button"
      onClick={() => toggleSort(col)}
      className={cx(
        "inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground",
        className,
      )}
    >
      {children}
      {sortKey === col ? (
        <span>{sortDir === "desc" ? "↓" : "↑"}</span>
      ) : (
        <span className="opacity-30">↕</span>
      )}
    </button>
  );

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
                <select
                  value={detectorId}
                  onChange={(e) => setDetectorId(e.target.value)}
                  className="ui-select h-8 text-xs font-mono"
                  aria-label="Detector filter"
                >
                  <option value="">All detectors</option>
                  {Object.entries(DETECTOR_LABELS).map(([id, label]) => (
                    <option key={id} value={id}>{label}</option>
                  ))}
                </select>
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
              <div className="flex items-center gap-2">
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as UebaSeverity | "all")}
                  className="ui-select h-8 text-xs font-mono"
                  aria-label="Severity filter"
                >
                  {SEVERITY_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value as UebaFindingStatus | "all")}
                  className="ui-select h-8 text-xs font-mono"
                  aria-label="Status filter"
                >
                  {STATUS_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => load({ replace: true })}
                  disabled={loading}
                  className="ui-btn-secondary h-8 px-2.5 text-xs font-mono"
                  aria-label="Refresh"
                >
                  Refresh
                </button>
              </div>
            }
          />

          {error ? (
            <DataQueryStateBanner
              tone="danger"
              message={error}
              right={
                <button
                  type="button"
                  onClick={() => load({ replace: true })}
                  className="underline"
                >
                  Retry
                </button>
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
            <div className="overflow-x-hidden">
              <table className="w-full text-[12px]" aria-label="Anomaly findings">
                <thead>
                  <tr className="border-b border-border/60">
                    <th className="py-2 pl-3 pr-2 text-left">
                      <SortHeader col="risk_score">Risk</SortHeader>
                    </th>
                    <th className="px-2 py-2 text-left">
                      <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                        Entity
                      </span>
                    </th>
                    <th className="px-2 py-2 text-left">
                      <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                        Detector / Metric
                      </span>
                    </th>
                    <th className="px-2 py-2 text-left">
                      <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                        Observed → Expected
                      </span>
                    </th>
                    <th className="px-2 py-2 text-left">
                      <SortHeader col="last_seen_at">Last seen</SortHeader>
                    </th>
                    <th className="px-2 py-2 text-left">
                      <SortHeader col="first_seen_at">First seen</SortHeader>
                    </th>
                    <th className="px-2 py-2 text-right">
                      <SortHeader col="occurrence_count">Hits</SortHeader>
                    </th>
                    <th className="py-2 pl-2 pr-3 text-left">
                      <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                        MITRE
                      </span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((row) => (
                    <tr
                      key={row.id}
                      onClick={() => {
                        setSelectedFinding(row);
                        setDrawerOpen(true);
                      }}
                      className="cursor-pointer border-b border-border/40 hover:bg-muted/10 transition-colors"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          setSelectedFinding(row);
                          setDrawerOpen(true);
                        }
                      }}
                    >
                      <td className="py-2.5 pl-3 pr-2">
                        <div className="flex flex-col gap-1">
                          <SeverityPill variant={severityVariant(row.severity)}>
                            {row.severity === "informational" ? "info" : row.severity}
                          </SeverityPill>
                          <span className="font-mono text-[10px] text-muted-foreground">
                            risk {row.risk_score}
                          </span>
                        </div>
                      </td>
                      <td className="px-2 py-2.5">
                        <div className="max-w-[160px]">
                          <div className="truncate font-mono text-[12px] font-medium text-foreground" title={row.entity_value}>
                            {row.entity_value}
                          </div>
                          <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                            {row.entity_type}
                            {row.agent_id ? ` · ${row.agent_id}` : ""}
                          </div>
                          {row.agent_id && row.agent_id !== row.entity_value && (
                            <div className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
                              {row.agent_id}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-2 py-2.5">
                        <div className="max-w-[140px]">
                          <div className="truncate text-[12px] text-foreground" title={detectorLabel(row.detector_id)}>
                            {detectorLabel(row.detector_id)}
                          </div>
                          <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                            {metricLabel(row.metric_name)}
                          </div>
                        </div>
                      </td>
                      <td className="px-2 py-2.5">
                        <div className="font-mono text-[11px]">
                          <span className="font-semibold text-foreground">
                            {row.observed_value != null ? formatMetricValue(row.observed_value, row.metric_name) : "—"}
                          </span>
                          {row.expected_value != null && (
                            <span className="text-muted-foreground">
                              {" → "}{formatMetricValue(row.expected_value, row.metric_name)}
                            </span>
                          )}
                        </div>
                        {row.deviation_score != null && (
                          <div className="mt-1 flex items-center gap-1.5">
                            <div className="h-1 w-14 overflow-hidden rounded-full bg-muted/40">
                              <div
                                className={cx("h-full rounded-full", riskBarClass(row.risk_score))}
                                style={{ width: `${Math.min(100, row.risk_score)}%` }}
                              />
                            </div>
                            <span className="font-mono text-[10px] text-muted-foreground">
                              z={row.deviation_score.toFixed(1)}
                            </span>
                          </div>
                        )}
                      </td>
                      <td className="px-2 py-2.5 font-mono text-[11px] text-muted-foreground">
                        <span title={formatTimestamp(row.last_seen_at)}>
                          {relativeTime(row.last_seen_at)}
                        </span>
                      </td>
                      <td className="px-2 py-2.5 font-mono text-[11px] text-muted-foreground">
                        <span title={formatTimestamp(row.first_seen_at)}>
                          {relativeTime(row.first_seen_at)}
                        </span>
                      </td>
                      <td className="px-2 py-2.5 text-right font-mono text-[11px] text-muted-foreground">
                        {row.occurrence_count}
                      </td>
                      <td className="py-2.5 pl-2 pr-3">
                        {row.mitre_technique_id ? (
                          <div className="max-w-[110px]">
                            <div className="font-mono text-[10px] text-muted-foreground">
                              {row.mitre_technique_id}
                            </div>
                            {row.mitre_tactic ? (
                              <div className="mt-0.5 truncate text-[10px] text-muted-foreground/70" title={row.mitre_tactic}>
                                {row.mitre_tactic.replace(/_/g, " ")}
                              </div>
                            ) : null}
                          </div>
                        ) : (
                          <span className="text-[10px] text-muted-foreground/40">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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
      />
    </div>
  );
}
