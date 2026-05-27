import { useEffect, useRef } from "react";

import { Button } from "@/shared/components/Button";
import {
  DataPaginationFooter,
  DataQueryStateBanner,
  DataStatsStrip,
  DataViewToolbar,
  DebouncedSearchInput,
} from "@/shared/components/DataView";
import EmptyState from "@/shared/components/EmptyState";
import Loading from "@/shared/components/Loading";
import { Panel } from "@/shared/components/Panel";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextInput } from "@/shared/components/TextInput";
import { cx } from "@/shared/lib/cx";

import type { AlertsPageModel } from "../hooks/useAlertsPageModel";
import SeverityFilter from "./SeverityFilter";
import { AlertDrawer } from "./drawer/AlertDrawer";
import { AlertsTable } from "./AlertsTable";

export function AlertsWorkspace({ model }: { model: AlertsPageModel }) {
  const { query, data, filters, bulk, actions, openDrawerFor, handleRunAll } = model;
  const { view, patch } = query;

  const panelBodyRef = useRef<HTMLDivElement | null>(null);
  const loadMoreSentinelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!view.infinite_scroll) return;
    const root = panelBodyRef.current;
    const target = loadMoreSentinelRef.current;
    if (!root || !target) return;

    const obs = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          data.loadMore();
        }
      },
      { root, rootMargin: "320px 0px" },
    );

    obs.observe(target);
    return () => obs.disconnect();
  }, [view.infinite_scroll, data]);

  const panelHeightClass = "h-[560px] xl:h-[calc(100vh-270px)]";
  const isInitialLoading = data.loading && data.alerts.length === 0;

  const headerRight = (() => {
    if (data.loading && data.alerts.length === 0) return "Loading…";
    const base = `${filters.filtered.length} alerts`;
    if (!data.lastRefresh) return base;
    const hh = String(data.lastRefresh.getHours()).padStart(2, "0");
    const mm = String(data.lastRefresh.getMinutes()).padStart(2, "0");
    const ss = String(data.lastRefresh.getSeconds()).padStart(2, "0");
    return `${base} · refreshed ${hh}:${mm}:${ss}`;
  })();

  return (
    <div className="space-y-4">
      <DataViewToolbar
        left={
          <div>
            <h2 className="text-lg font-semibold">Alert queue</h2>
            <div className="text-xs text-muted-foreground">
              Inspect alert triage queue, pivot into evidence, and tune detections from the same workflow.
            </div>
          </div>
        }
        right={
          <div className="flex flex-wrap items-center gap-2">
            <DebouncedSearchInput
              value={view.search}
              onChange={(value) => patch({ search: value })}
              placeholder="Search rule, IP, technique, description..."
              className="h-9 min-w-[220px] max-w-[360px]"
            />
            <SeverityFilter value={view.severity} onChange={(value) => patch({ severity: value })} />
            <SelectInput
              value={view.status}
              onChange={(event) => patch({ status: event.target.value })}
              className="h-9 w-[150px] font-mono text-xs"
              title="Alert lifecycle status"
            >
              <option value="all">All status</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="investigating">Investigating</option>
              <option value="closed">Closed</option>
            </SelectInput>
            <TextInput
              value={view.rule_id}
              onChange={(event) => patch({ rule_id: event.target.value })}
              placeholder="Rule ID (exact)"
              className="h-9 w-[210px]"
              title="Exact server-side rule filter"
            />
            <Button
              variant="subtle"
              size="lg"
              onClick={() => patch({ density: view.density === "comfortable" ? "compact" : "comfortable" })}
              title="Toggle row density"
            >
              {view.density === "compact" ? "Compact" : "Comfort"}
            </Button>
            <Button
              variant={view.infinite_scroll ? "secondary" : "subtle"}
              size="lg"
              onClick={() => patch({ infinite_scroll: !view.infinite_scroll })}
              title="Auto-load older pages when scrolling"
            >
              {view.infinite_scroll ? "Infinite" : "Manual"}
            </Button>
            <Button
              variant="subtle"
              size="lg"
              onClick={() => data.loadHead("merge")}
              disabled={data.loading}
              title="Refresh queue"
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              size="lg"
              onClick={handleRunAll}
              disabled={actions.running}
              title="Run all rules now"
            >
              {actions.running ? "Running…" : "Run rules"}
            </Button>
          </div>
        }
      />

      <DataQueryStateBanner
        tone={data.error ? "danger" : "neutral"}
        message={
          data.error
            ? data.error
            : `source realtime+cursor · mode ${view.infinite_scroll ? "infinite" : "manual"} · ${headerRight}`
        }
        right={`${bulk.selectedRows.length} selected`}
      />

      <DataStatsStrip
        stats={[
          { label: "Visible", value: filters.filtered.length, hint: `${data.alerts.length} loaded` },
          { label: "Critical/High", value: filters.severityBreakdown.critical + filters.severityBreakdown.high },
          { label: "Medium/Low", value: filters.severityBreakdown.medium + filters.severityBreakdown.low },
          { label: "Unknown", value: filters.severityBreakdown.unknown },
          { label: "Severity filter", value: view.severity },
          { label: "Status filter", value: view.status },
          { label: "Rule filter", value: view.rule_id || "-" },
          { label: "Density", value: view.density },
          { label: "Selected", value: bulk.selectedRows.length },
        ]}
      />

      {bulk.selectedRows.length > 0 ? (
        <DataViewToolbar
          className="py-2"
          left={<div className="text-xs text-muted-foreground">{bulk.selectedRows.length} row(s) selected</div>}
          right={
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="subtle"
                size="md"
                onClick={() => bulk.selectedRows.length > 0 && openDrawerFor(bulk.selectedRows[0])}
              >
                Open first evidence
              </Button>
              <Button
                variant="subtle"
                size="md"
                onClick={() =>
                  bulk.selectedRows.length > 0 && actions.openSelectedRuleEditor(bulk.selectedRows[0])
                }
              >
                Edit selected rule
              </Button>
              <Button
                variant="subtle"
                size="md"
                onClick={() => bulk.selectedRows.length > 0 && actions.pivotToEvents(bulk.selectedRows[0])}
              >
                Pivot to events
              </Button>
              <Button variant="subtle" size="md" onClick={bulk.clearSelectedRows}>
                Clear selection
              </Button>
            </div>
          }
        />
      ) : null}

      <Panel
        title="Queue"
        actions={<span className="text-[10px] font-mono text-muted-foreground">{headerRight}</span>}
        scrollY
        className={cx(panelHeightClass)}
        bodyRef={panelBodyRef}
        bodyClassName="p-0"
      >
        {isInitialLoading ? (
          <div className="p-4">
            <Loading label="Loading alerts…" />
          </div>
        ) : filters.filtered.length === 0 ? (
          <div className="p-4">
            <EmptyState title="No alerts" description="No alerts match the current filters." />
          </div>
        ) : (
          <div className="relative">
            <AlertsTable
              rows={filters.filtered}
              selectedId={model.drawer.selected?.id ?? null}
              onEdit={openDrawerFor}
              density={view.density}
              selectedRowIds={bulk.selectedRowIds}
              onToggleRow={bulk.toggleRowSelection}
              onToggleAllRows={bulk.toggleAllVisibleRows}
            />

            <div className="sticky bottom-0 left-0 right-0 border-t border-border/60 bg-background/70 px-4 py-3 backdrop-blur">
              <DataPaginationFooter
                totalCount={filters.filtered.length}
                pageSize={view.page_size}
                onPageSizeChange={(next) => patch({ page_size: next })}
                pageSizeOptions={[50, 100, 200]}
                hasMore={data.hasMore}
                loadingMore={data.loadingMore}
                onLoadMore={data.loadMore}
                loadMoreLabel="Load older"
                error={data.error}
                onRetry={data.error ? () => data.loadHead("merge") : undefined}
              />
            </div>

            <div ref={loadMoreSentinelRef} className="h-6" />
          </div>
        )}
      </Panel>

      <AlertDrawer model={model} />
    </div>
  );
}
