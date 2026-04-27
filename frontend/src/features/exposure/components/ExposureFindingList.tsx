import { useMemo } from "react";

import { Button } from "@/shared/components/Button";
import { DataPaginationFooter, DataTableSkeleton, DataQueryStateBanner } from "@/shared/components/DataView";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { CursorPage } from "@/shared/types/pagination";

import { ExposureFinding } from "../types";
import {
  exposureSeverityVariant,
  exposureStatusVariant,
  formatExposureConfidence,
  formatExposureTimestamp,
  truncateText,
} from "../utils";
import { ExposureReasonCodes } from "./ExposureReasonCodes";

type Props = {
  page: CursorPage<ExposureFinding> | null;
  loading?: boolean;
  loadingMore?: boolean;
  refreshing?: boolean;
  error?: string | null;
  onSelect?: (finding: ExposureFinding) => void;
  onLoadMore?: () => void;
  onRetry?: () => void;
  selectedFindingKey?: string | null;
};

export function ExposureFindingList({
  page,
  loading,
  loadingMore,
  refreshing,
  error,
  onSelect,
  onLoadMore,
  onRetry,
  selectedFindingKey,
}: Props) {
  const rows = page?.items ?? [];
  const isInitialLoading = Boolean(loading && rows.length === 0);

  const columns = useMemo<Array<Column<ExposureFinding>>>(
    () => [
      {
        key: "finding_type",
        title: "Finding",
        width: 220,
        render: (finding) => (
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-foreground">{finding.title}</div>
            <div className="mt-1 font-mono text-[11px] text-muted-foreground">{finding.finding_type}</div>
          </div>
        ),
      },
      {
        key: "severity",
        title: "Severity",
        width: 92,
        render: (finding) => (
          <SeverityPill variant={exposureSeverityVariant(finding.severity)}>
            {finding.severity}
          </SeverityPill>
        ),
      },
      {
        key: "score_delta",
        title: "Score Delta",
        width: 92,
        className: "font-mono text-[12px]",
        render: (finding) => (
          <span className={finding.score_delta > 0 ? "text-danger" : "text-foreground"}>
            {finding.score_delta > 0 ? `+${finding.score_delta}` : finding.score_delta}
          </span>
        ),
      },
      {
        key: "confidence",
        title: "Confidence",
        width: 92,
        className: "font-mono text-[12px]",
        render: (finding) => formatExposureConfidence(finding.confidence),
      },
      {
        key: "summary",
        title: "Summary",
        width: 320,
        render: (finding) => (
          <div className="text-[12px] text-muted-foreground">
            {truncateText(finding.summary || finding.title, 180)}
          </div>
        ),
      },
      {
        key: "evidence_refs",
        title: "Evidence",
        width: 92,
        className: "font-mono text-[12px]",
        render: (finding) => `${finding.evidence_refs.length} refs`,
      },
      {
        key: "reason_codes",
        title: "Reason Codes",
        width: 220,
        render: (finding) => <ExposureReasonCodes codes={finding.reason_codes.slice(0, 4)} />,
      },
      {
        key: "status",
        title: "Status",
        width: 112,
        render: (finding) => <StatusPill variant={exposureStatusVariant(finding.status)}>{finding.status}</StatusPill>,
      },
      {
        key: "related_node_keys",
        title: "Related Nodes",
        width: 220,
        render: (finding) => (
          <div className="text-[11px] text-muted-foreground">
            {finding.related_node_keys.length > 0 ? truncateText(finding.related_node_keys.join(" · "), 100) : "No related nodes"}
          </div>
        ),
      },
      {
        key: "last_seen_at",
        title: "Last Seen",
        width: 152,
        className: "font-mono text-[11px] text-muted-foreground",
        render: (finding) => formatExposureTimestamp(finding.last_seen_at),
      },
    ],
    [],
  );

  if (isInitialLoading) {
    return <DataTableSkeleton rows={10} columns={8} />;
  }

  if (error && rows.length === 0) {
    return (
      <InlineAlert tone="danger">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span>{error}</span>
          {onRetry ? (
            <Button variant="danger" size="sm" onClick={onRetry}>
              Retry
            </Button>
          ) : null}
        </div>
      </InlineAlert>
    );
  }

  if (rows.length === 0) return null;

  return (
    <div className="space-y-3">
      {error && rows.length > 0 ? (
        <DataQueryStateBanner
          tone="danger"
          message={error}
          right={
            onRetry ? (
              <Button variant="danger" size="sm" onClick={onRetry}>
                Retry
              </Button>
            ) : undefined
          }
        />
      ) : null}

      <div className="flex items-center justify-between gap-2">
        <div className="text-[11px] font-mono text-muted-foreground">{rows.length} findings loaded</div>
        {refreshing ? <div className="text-[11px] font-mono text-muted-foreground">Refreshing…</div> : null}
      </div>

      <Table
        columns={columns}
        rows={rows}
        rowKey={(finding) => finding.finding_key}
        stickyHeader
        selectedRowKey={selectedFindingKey ?? null}
        onRowClick={(finding) => onSelect?.(finding)}
        className="text-sm"
        footer={
          <DataPaginationFooter
            totalCount={rows.length}
            pageSize={50}
            onPageSizeChange={() => undefined}
            pageSizeOptions={[50]}
            hasMore={Boolean(page?.has_more)}
            loadingMore={Boolean(loadingMore)}
            onLoadMore={onLoadMore}
            error={rows.length > 0 ? error : null}
            onRetry={onRetry}
          />
        }
      />
    </div>
  );
}
