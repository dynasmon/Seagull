import { useMemo } from "react";

import { Button } from "@/shared/components/Button";
import { DataPaginationFooter, DataTableSkeleton, DataQueryStateBanner } from "@/shared/components/DataView";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { StatusPill } from "@/shared/components/StatusPill";
import { Table, type Column } from "@/shared/components/Table";
import { CursorPage } from "@/shared/types/pagination";

import { ExposureAssetPosture } from "../types";
import {
  exposureSeverityVariant,
  exposureStatusVariant,
  formatExposureConfidence,
  formatExposureScore,
  formatExposureTimestamp,
  summarizeEvidenceCounts,
  totalEvidenceCount,
} from "../utils";
import { ExposureReasonCodes } from "./ExposureReasonCodes";

type Props = {
  page: CursorPage<ExposureAssetPosture> | null;
  loading?: boolean;
  loadingMore?: boolean;
  refreshing?: boolean;
  error?: string | null;
  compact?: boolean;
  pageSize?: number;
  selectedAssetKey?: string | null;
  onCompactChange?: (next: boolean) => void;
  onPageSizeChange?: (next: number) => void;
  onSelect?: (asset: ExposureAssetPosture) => void;
  onViewGraph?: (asset: ExposureAssetPosture) => void;
  onLoadMore?: () => void;
  onRetry?: () => void;
};

function AssetConfidenceCell({ confidence }: { confidence: number }) {
  const value = Math.max(0, Math.min(100, Math.round(confidence)));
  return (
    <div className="flex min-w-[104px] items-center gap-2">
      <span className="shrink-0 font-mono text-[12px] text-foreground">{formatExposureConfidence(value)}</span>
      <div className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-muted/60">
        <div
          className={value >= 85 ? "h-full bg-success" : value >= 60 ? "h-full bg-primary" : "h-full bg-warning"}
          style={{ width: `${value}%` }}
        />
      </div>
    </div>
  );
}

export function ExposureAssetTable({
  page,
  loading,
  loadingMore,
  refreshing,
  error,
  compact = false,
  pageSize = 50,
  selectedAssetKey,
  onCompactChange,
  onPageSizeChange,
  onSelect,
  onViewGraph,
  onLoadMore,
  onRetry,
}: Props) {
  const rows = page?.items ?? [];
  const isInitialLoading = Boolean(loading && rows.length === 0);

  const columns = useMemo<Array<Column<ExposureAssetPosture>>>(
    () => [
      {
        key: "risk_score",
        title: "Risk",
        width: 96,
        className: "font-mono",
        render: (asset) => (
          <div className="flex items-baseline gap-1.5">
            <span className="text-base font-semibold leading-none text-foreground">
              {formatExposureScore(asset.risk_score)}
            </span>
            <span className="min-w-0 truncate text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
              {asset.criticality}
            </span>
          </div>
        ),
      },
      {
        key: "severity",
        title: "Severity",
        width: 96,
        render: (asset) => <SeverityPill variant={exposureSeverityVariant(asset.severity)}>{asset.severity}</SeverityPill>,
      },
      {
        key: "display_name",
        title: "Asset",
        width: 260,
        render: (asset) => {
          const hostEnv = [asset.hostname, asset.environment].filter(Boolean).join(" · ");
          return (
            <div
              className="flex min-w-0 items-center gap-1.5"
              title={`${asset.display_name}\n${asset.asset_key}${hostEnv ? `\n${hostEnv}` : ""}`}
            >
              <span className="min-w-0 truncate text-sm font-semibold text-foreground">{asset.display_name}</span>
              <span className="min-w-0 max-w-[50%] shrink-0 truncate font-mono text-[11px] text-muted-foreground">{asset.asset_key}</span>
            </div>
          );
        },
      },
      {
        key: "agent_id",
        title: "Agent",
        width: 180,
        className: "font-mono text-[12px]",
        render: (asset) => asset.agent_id || <span className="text-muted-foreground">-</span>,
      },
      {
        key: "status",
        title: "Status",
        width: 100,
        render: (asset) => <StatusPill variant={exposureStatusVariant(asset.status)}>{asset.status}</StatusPill>,
      },
      {
        key: "confidence",
        title: "Confidence",
        width: 132,
        render: (asset) => <AssetConfidenceCell confidence={asset.confidence} />,
      },
      {
        key: "reason_codes",
        title: "Reason Codes",
        width: 240,
        render: (asset) => <ExposureReasonCodes codes={asset.reason_codes.slice(0, compact ? 2 : 4)} nowrap />,
      },
      {
        key: "evidence_counts",
        title: "Evidence",
        width: 180,
        render: (asset) => (
          <div className="flex min-w-0 items-center gap-1.5 text-[11px]">
            <span className="shrink-0 font-mono text-foreground">{totalEvidenceCount(asset.evidence_counts)} refs</span>
            <span className="min-w-0 truncate text-muted-foreground">{summarizeEvidenceCounts(asset.evidence_counts, { limit: compact ? 2 : 3 })}</span>
          </div>
        ),
      },
      {
        key: "top_recommendations",
        title: "Top Recommendation",
        width: 280,
        render: (asset) => {
          const top = asset.top_recommendations[0];
          if (!top) return <span className="text-muted-foreground">No recommendation</span>;
          return (
            <div
              className="flex min-w-0 items-center gap-1.5"
              title={`${top.title}${!compact && top.reason ? `\n${top.reason}` : ""}`}
            >
              <span className="min-w-0 truncate text-[12px] font-medium text-foreground">{top.title}</span>
              {!compact && top.reason ? (
                <span className="min-w-0 max-w-[55%] shrink-0 truncate text-[11px] text-muted-foreground">{top.reason}</span>
              ) : null}
            </div>
          );
        },
      },
      {
        key: "last_seen_at",
        title: "Last Seen",
        width: 152,
        className: "font-mono text-[11px] text-muted-foreground",
        render: (asset) => formatExposureTimestamp(asset.last_seen_at),
      },
      {
        key: "updated_at",
        title: "Updated",
        width: 152,
        className: "font-mono text-[11px] text-muted-foreground",
        render: (asset) => formatExposureTimestamp(asset.updated_at),
      },
      {
        key: "actions",
        title: "Actions",
        align: "right",
        width: 92,
        render: (asset) => (
          <Button
            variant="ghost"
            size="sm"
            onClick={(event) => {
              event.stopPropagation();
              onViewGraph?.(asset);
            }}
          >
            Graph
          </Button>
        ),
      },
    ],
    [compact, onViewGraph],
  );

  if (isInitialLoading) {
    return <DataTableSkeleton rows={10} columns={11} />;
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
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-[11px] font-mono text-muted-foreground">
          {rows.length} assets loaded
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {refreshing ? <span className="text-[11px] font-mono text-muted-foreground">Refreshing…</span> : null}
          <Button variant={compact ? "secondary" : "subtle"} size="sm" onClick={() => onCompactChange?.(!compact)}>
            {compact ? "Compact rows" : "Comfortable rows"}
          </Button>
        </div>
      </div>

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

      <Table
        columns={columns}
        rows={rows}
        rowKey={(asset) => asset.asset_key}
        compact={compact}
        stickyHeader
        scrollX
        selectedRowKey={selectedAssetKey ?? null}
        onRowClick={(asset) => onSelect?.(asset)}
        className="text-sm"
        footer={
          <DataPaginationFooter
            totalCount={rows.length}
            pageSize={pageSize}
            onPageSizeChange={(next) => onPageSizeChange?.(next)}
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
