import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Link, useNavigate } from "react-router-dom";

import { Button } from "@/shared/components/Button";
import { Card } from "@/shared/components/Card";
import {
  DataQueryStateBanner,
  DataStatsStrip,
  DataViewToolbar,
  DebouncedSearchInput,
} from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import { InlineAlert } from "@/shared/components/InlineAlert";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { Toolbar } from "@/shared/components/Toolbar";
import { useLiveRefresh, usePortalRealtimeSubscription } from "@/shared/realtime";

import SeverityFilter from "@/features/alerts/components/SeverityFilter";

import {
  getCorrelationIncident,
  getCorrelationIncidents,
  runCorrelations,
  updateCorrelationIncidentStatus,
} from "../api";
import CorrelationIncidentDrawer from "../components/CorrelationIncidentDrawer";
import CorrelationIncidentTable from "../components/CorrelationIncidentTable";
import {
  correlationMitrePreview,
  extractCorrelationMitreMetadata,
} from "../components/correlationUtils";
import type {
  CorrelationDurableIncident,
  CorrelationIncidentDetail,
  CorrelationLifecycleStatus,
  CorrelationMitreMetadata,
  CorrelationRuleRunResult,
} from "../types";
import { correlationSeverityVariant } from "../components/correlationUtils";

type IncidentSortKey =
  | "status"
  | "severity"
  | "risk_score"
  | "confidence"
  | "correlation_rule_name"
  | "entity"
  | "started_at"
  | "last_seen_at"
  | "alert_count"
  | "unique_rules_count"
  | "stage_hits_count";

function compareNullableNumbers(left?: number | null, right?: number | null) {
  return (left ?? -1) - (right ?? -1);
}

function compareText(left: string, right: string) {
  return left.localeCompare(right);
}

export default function CorrelationIncidentsPage() {
  const navigate = useNavigate();

  const reqSeq = useRef(0);
  const detailCacheRef = useRef<Record<number, CorrelationIncidentDetail>>({});
  const pendingDetailsRef = useRef(new Map<number, Promise<CorrelationIncidentDetail | null>>());

  const [rows, setRows] = useState<CorrelationDurableIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detailCache, setDetailCache] = useState<Record<number, CorrelationIncidentDetail>>({});
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState<CorrelationLifecycleStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<CorrelationLifecycleStatus | "all">("open");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [pageSize, setPageSize] = useState(25);
  const [sort, setSort] = useState<{ key: IncidentSortKey; direction: "asc" | "desc" }>({
    key: "last_seen_at",
    direction: "desc",
  });

  const [runLimit, setRunLimit] = useState(500);
  const [runLookback, setRunLookback] = useState(1440);
  const [runSampleLimit, setRunSampleLimit] = useState(25);
  const [runBusy, setRunBusy] = useState(false);
  const [runResult, setRunResult] = useState<CorrelationRuleRunResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    detailCacheRef.current = detailCache;
  }, [detailCache]);

  const loadIncidents = useCallback(async ({ signal, background = false }: { signal?: AbortSignal; background?: boolean } = {}) => {
    const mySeq = ++reqSeq.current;
    if (!background) setLoading(true);
    setError(null);
    try {
      const nextRows = await getCorrelationIncidents({
        status: statusFilter,
        limit: pageSize,
        offset: 0,
        signal,
      });
      if (signal?.aborted || reqSeq.current !== mySeq) return;
      setRows(nextRows || []);
      setSelectedId((current) => {
        if (current === null) return null;
        return (nextRows || []).some((row) => row.id === current) ? current : null;
      });
    } catch (cause: any) {
      if (signal?.aborted || reqSeq.current !== mySeq) return;
      setError(cause?.message || "Failed to load correlation incidents");
      if (!background) setRows([]);
    } finally {
      if (signal?.aborted || reqSeq.current !== mySeq) return;
      if (!background) setLoading(false);
    }
  }, [pageSize, statusFilter]);

  const fetchIncidentDetail = useCallback(async (
    incidentId: number,
    opts?: {
      signal?: AbortSignal;
      silent?: boolean;
      force?: boolean;
      expectedUpdatedAt?: string;
    },
  ) => {
    const cached = detailCacheRef.current[incidentId];
    if (
      !opts?.force
      && cached
      && (!opts?.expectedUpdatedAt || cached.updated_at === opts.expectedUpdatedAt)
    ) {
      return cached;
    }

    const existing = pendingDetailsRef.current.get(incidentId);
    if (existing) return existing;

    if (!opts?.silent) {
      setDetailLoading(true);
      setDetailError(null);
    }

    const promise = getCorrelationIncident(incidentId, { signal: opts?.signal })
      .then((detail) => {
        if (opts?.signal?.aborted) return null;
        setDetailCache((prev) => ({ ...prev, [incidentId]: detail }));
        return detail;
      })
      .catch((cause: any) => {
        if (!opts?.signal?.aborted && !opts?.silent) {
          setDetailError(cause?.message || "Failed to load incident detail");
        }
        return null;
      })
      .finally(() => {
        pendingDetailsRef.current.delete(incidentId);
        if (!opts?.silent) setDetailLoading(false);
      });

    pendingDetailsRef.current.set(incidentId, promise);
    return promise;
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void loadIncidents({ signal: controller.signal });
    return () => controller.abort();
  }, [loadIncidents]);

  useEffect(() => {
    const controller = new AbortController();
    const staleRows = rows.filter((row) => {
      const cached = detailCacheRef.current[row.id];
      return !cached || cached.updated_at !== row.updated_at;
    });
    if (staleRows.length === 0) return () => controller.abort();

    void Promise.allSettled(
      staleRows.map((row) =>
        fetchIncidentDetail(row.id, {
          signal: controller.signal,
          silent: true,
          expectedUpdatedAt: row.updated_at,
        }),
      ),
    );
    return () => controller.abort();
  }, [fetchIncidentDetail, rows]);

  const live = useLiveRefresh({
    profile: "admin",
    refresh: ({ signal }) => loadIncidents({ signal, background: true }),
    onError: (cause) => {
      if (rows.length === 0) {
        setError((cause as { message?: string })?.message || "Failed to refresh correlation incidents");
      }
    },
  });

  usePortalRealtimeSubscription("ui.alerts.invalidate", () => {
    live.invalidate();
  });
  usePortalRealtimeSubscription("alert.created", () => {
    live.invalidate();
  });
  usePortalRealtimeSubscription("alert.updated", () => {
    live.invalidate();
  });
  usePortalRealtimeSubscription("ui.investigations.invalidate", () => {
    live.invalidate("invalidate");
  });

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const severity = severityFilter.toLowerCase();

    return rows.filter((row) => {
      if (severity !== "all" && String(row.severity || "").toLowerCase() !== severity) return false;
      if (!needle) return true;
      const entity = row.entity_value || row.group_value;
      const mitre = correlationMitrePreview(
        extractCorrelationMitreMetadata(detailCache[row.id] || null),
        1,
      ).join(" ");
      const haystack = [
        row.correlation_rule_name,
        row.dedup_key,
        row.group_by,
        row.group_value,
        row.entity_type || "",
        entity || "",
        row.status,
        ...(row.unique_rules || []),
        mitre,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [detailCache, query, rows, severityFilter]);

  const sortedRows = useMemo(() => {
    const nextRows = [...filtered];
    nextRows.sort((left, right) => {
      let result = 0;
      if (sort.key === "status") result = compareText(String(left.status), String(right.status));
      else if (sort.key === "severity") result = compareText(String(left.severity), String(right.severity));
      else if (sort.key === "risk_score") result = compareNullableNumbers(left.risk_score, right.risk_score);
      else if (sort.key === "confidence") result = compareNullableNumbers(left.confidence, right.confidence);
      else if (sort.key === "correlation_rule_name") result = compareText(left.correlation_rule_name, right.correlation_rule_name);
      else if (sort.key === "entity") result = compareText(String(left.entity_value || left.group_value), String(right.entity_value || right.group_value));
      else if (sort.key === "started_at") result = new Date(left.started_at).getTime() - new Date(right.started_at).getTime();
      else if (sort.key === "last_seen_at") result = new Date(left.last_seen_at).getTime() - new Date(right.last_seen_at).getTime();
      else if (sort.key === "alert_count") result = left.alert_count - right.alert_count;
      else if (sort.key === "unique_rules_count") result = (left.unique_rules?.length || 0) - (right.unique_rules?.length || 0);
      else if (sort.key === "stage_hits_count") result = Object.keys(left.stage_hits || {}).length - Object.keys(right.stage_hits || {}).length;
      return sort.direction === "asc" ? result : result * -1;
    });
    return nextRows;
  }, [filtered, sort]);

  const selectedIncident = useMemo(
    () => rows.find((row) => row.id === selectedId) || null,
    [rows, selectedId],
  );
  const selectedDetail = selectedId === null ? null : detailCache[selectedId] || null;

  const mitreByIncidentId = useMemo(() => {
    const out: Record<number, CorrelationMitreMetadata | undefined> = {};
    for (const row of rows) {
      const detail = detailCache[row.id];
      out[row.id] = detail ? extractCorrelationMitreMetadata(detail) : undefined;
    }
    return out;
  }, [detailCache, rows]);

  const stats = useMemo(() => {
    const open = filtered.filter((row) => String(row.status) === "open").length;
    const triaged = filtered.filter((row) => String(row.status) === "triaged").length;
    const suppressed = filtered.filter((row) => String(row.status) === "suppressed").length;
    const criticalHigh = filtered.filter((row) => {
      const variant = correlationSeverityVariant(row.severity);
      return variant === "critical" || variant === "high";
    }).length;
    return { open, triaged, suppressed, criticalHigh };
  }, [filtered]);

  async function openIncident(incident: CorrelationDurableIncident) {
    setSelectedId(incident.id);
    await fetchIncidentDetail(incident.id, { expectedUpdatedAt: incident.updated_at });
  }

  async function handleStatusChange(status: CorrelationLifecycleStatus, summary: string) {
    if (!selectedIncident) return;
    setUpdatingStatus(status);
    setStatusError(null);
    try {
      const updated = await updateCorrelationIncidentStatus(selectedIncident.id, {
        status,
        summary: summary.trim() ? summary.trim() : null,
      });
      setRows((prev) => prev.map((row) => (row.id === updated.id ? { ...row, ...updated } : row)));
      setDetailCache((prev) => ({ ...prev, [updated.id]: updated }));
      live.markUpdated();
      void loadIncidents({ background: true });
    } catch (cause: any) {
      setStatusError(cause?.message || "Failed to update incident status");
    } finally {
      setUpdatingStatus(null);
    }
  }

  async function handleRunCorrelations() {
    setRunBusy(true);
    setRunError(null);
    try {
      const result = await runCorrelations({
        limit: runLimit,
        max_age_minutes: runLookback,
        sample_limit: runSampleLimit,
      });
      setRunResult(result);
      await loadIncidents({ background: true });
    } catch (cause: any) {
      setRunError(cause?.message || "Failed to run correlations");
    } finally {
      setRunBusy(false);
    }
  }

  const liveLabel = live.state.isFallbackPolling
    ? "fallback polling"
    : live.state.isReconnecting
      ? "reconnecting"
      : live.state.isLive
        ? "live"
        : "refreshing";

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={
          <div>
            <h2 className="text-lg font-semibold">Durable correlation incidents</h2>
            <div className="text-xs text-muted-foreground">
              Investigate persisted incidents with lifecycle status, evidence, MITRE context, and analyst actions.
            </div>
          </div>
        }
        right={
          <div className="flex flex-wrap items-center gap-2">
            <DebouncedSearchInput
              value={query}
              onChange={setQuery}
              placeholder="Search incident, entity, dedup key, MITRE..."
              className="h-9 min-w-[280px]"
            />
            <SelectInput
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as CorrelationLifecycleStatus | "all")}
              className="h-9"
            >
              <option value="all">All statuses</option>
              <option value="open">Open</option>
              <option value="triaged">Triaged</option>
              <option value="closed">Closed</option>
              <option value="suppressed">Suppressed</option>
            </SelectInput>
            <SeverityFilter value={severityFilter} onChange={setSeverityFilter} />
            <SelectInput value={String(pageSize)} onChange={(event) => setPageSize(Number(event.target.value))} className="h-9">
              <option value="25">25 incidents</option>
              <option value="50">50 incidents</option>
              <option value="100">100 incidents</option>
            </SelectInput>
            <Button variant="subtle" size="lg" onClick={() => void live.refreshNow()}>
              Refresh
            </Button>
          </div>
        }
      />

      <DataQueryStateBanner
        tone={error ? "danger" : runError ? "warning" : "neutral"}
        message={
          error
            ? error
            : runError
              ? runError
              : `${sortedRows.length} incidents shown · ${rows.length} fetched${runResult ? ` · last run scanned ${runResult.alerts_scanned} alerts` : ""}`
        }
        right={`${liveLabel}${live.state.isRefreshing ? " · syncing" : ""}`}
      />

      <DataStatsStrip
        stats={[
          { label: "Incidents", value: filtered.length },
          { label: "Open", value: stats.open },
          { label: "Triaged", value: stats.triaged },
          { label: "Suppressed", value: stats.suppressed },
          { label: "Critical/High", value: stats.criticalHigh },
          { label: "Selected", value: selectedIncident ? selectedIncident.id : "-" },
        ]}
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Panel
          title="Incident queue"
          subtitle="Status, evidence confidence, MITRE hints, and lifecycle state are all visible from the primary queue."
          actions={<span className="text-[10px] font-mono text-muted-foreground">Click a row to investigate</span>}
          className="min-h-[640px]"
          scrollY
        >
          {loading ? (
            <Loading label="Loading correlation incidents..." />
          ) : sortedRows.length === 0 ? (
            <div className="space-y-4">
              <EmptyState
                title="No incidents"
                description="No durable incidents match the current filters. Run correlations or relax the filters."
              />
              <div className="flex justify-center gap-2">
                <Button variant="primary" size="lg" onClick={() => void handleRunCorrelations()} disabled={runBusy}>
                  {runBusy ? "Running..." : "Run correlations"}
                </Button>
                <Link
                  to="/correlations/rules"
                  className="inline-flex h-9 items-center rounded-md border border-border/60 bg-muted/20 px-4 text-[12px] font-semibold text-muted-foreground transition-colors hover:bg-muted/35 hover:text-foreground"
                >
                  Open rules
                </Link>
              </div>
            </div>
          ) : (
            <CorrelationIncidentTable
              rows={sortedRows}
              selectedId={selectedId}
              sort={sort}
              onSortChange={(next) => setSort(next as { key: IncidentSortKey; direction: "asc" | "desc" })}
              onSelect={(incident) => void openIncident(incident)}
              mitreByIncidentId={mitreByIncidentId}
            />
          )}
        </Panel>

        <div className="space-y-4">
          <Card
            title="Execution"
            right={runBusy ? "Running" : runResult ? "Last run complete" : "Manual"}
          >
            <div className="space-y-3">
              <Toolbar
                left={<div className="text-sm text-muted-foreground">Refresh durable incidents from current alert evidence.</div>}
              />

              {runError ? <InlineAlert tone="danger">{runError}</InlineAlert> : null}

              <div className="grid gap-3">
                <label className="block">
                  <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Lookback</div>
                  <SelectInput value={String(runLookback)} onChange={(event) => setRunLookback(Number(event.target.value))}>
                    <option value="60">Last 60m</option>
                    <option value="360">Last 6h</option>
                    <option value="1440">Last 24h</option>
                    <option value="10080">Last 7d</option>
                  </SelectInput>
                </label>

                <label className="block">
                  <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Alert scan limit</div>
                  <SelectInput value={String(runLimit)} onChange={(event) => setRunLimit(Number(event.target.value))}>
                    <option value="200">200 alerts</option>
                    <option value="500">500 alerts</option>
                    <option value="1000">1,000 alerts</option>
                    <option value="2000">2,000 alerts</option>
                  </SelectInput>
                </label>

                <label className="block">
                  <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Evidence sample limit</div>
                  <SelectInput value={String(runSampleLimit)} onChange={(event) => setRunSampleLimit(Number(event.target.value))}>
                    <option value="10">10 samples</option>
                    <option value="25">25 samples</option>
                    <option value="50">50 samples</option>
                  </SelectInput>
                </label>

                <Button variant="primary" size="lg" onClick={() => void handleRunCorrelations()} disabled={runBusy}>
                  {runBusy ? "Running correlations..." : "Run correlations"}
                </Button>
              </div>

              {runResult ? (
                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-3 text-sm">
                  <div className="font-semibold text-foreground">Last run result</div>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-[12px] text-muted-foreground">
                    <div>Rules evaluated</div>
                    <div className="text-right font-mono text-foreground">{runResult.rules_evaluated}</div>
                    <div>Alerts scanned</div>
                    <div className="text-right font-mono text-foreground">{runResult.alerts_scanned}</div>
                    <div>Matches produced</div>
                    <div className="text-right font-mono text-foreground">{runResult.incidents.length}</div>
                  </div>
                </div>
              ) : (
                <div className="rounded-lg border border-border/60 bg-background/20 px-3 py-3 text-sm text-muted-foreground">
                  Manual execution still exists, but the page now stays incident-centered instead of living inside one temporary run result.
                </div>
              )}
            </div>
          </Card>

          <Card title="Workflow">
            <div className="space-y-2 text-sm text-muted-foreground">
              <div>1. Run or wait for correlations to update durable incidents.</div>
              <div>2. Open a row to inspect evidence, MITRE hints, and raw context.</div>
              <div>3. Persist analyst lifecycle state directly from the drawer.</div>
              <div>4. Pivot into alerts or investigations when the incident warrants deeper work.</div>
            </div>
          </Card>
        </div>
      </div>

      <CorrelationIncidentDrawer
        open={selectedId !== null}
        incident={selectedIncident}
        detail={selectedDetail}
        loading={detailLoading}
        error={detailError}
        updatingStatus={updatingStatus}
        statusError={statusError}
        onClose={() => {
          setSelectedId(null);
          setDetailError(null);
          setStatusError(null);
        }}
        onRefresh={() => {
          if (!selectedIncident) return;
          void fetchIncidentDetail(selectedIncident.id, { force: true, expectedUpdatedAt: selectedIncident.updated_at });
        }}
        onStatusChange={(status, summary) => void handleStatusChange(status, summary)}
        onOpenAlerts={() => {
          if (!selectedIncident) return;
          const entity = selectedIncident.entity_value || selectedIncident.group_value;
          navigate(`/alerts/queue?search=${encodeURIComponent(entity || selectedIncident.correlation_rule_name)}`);
        }}
        onOpenInvestigations={() => {
          if (!selectedIncident) return;
          const entity = selectedIncident.entity_value || selectedIncident.group_value;
          navigate(`/investigations?search=${encodeURIComponent(entity || selectedIncident.correlation_rule_name)}`);
        }}
      />
    </div>
  );
}
