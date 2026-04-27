import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { CursorPage } from "@/shared/types/pagination";
import { ExposureAssetPosture, ExposureSeverity } from "../types";

function sevVariant(s: ExposureSeverity) {
  if (s === "informational") return "info" as const;
  if (s === "unknown") return "neutral" as const;
  return s as "critical" | "high" | "medium" | "low";
}

type Props = {
  page: CursorPage<ExposureAssetPosture> | null;
  loading?: boolean;
  onSelect?: (asset: ExposureAssetPosture) => void;
  onViewGraph?: (asset: ExposureAssetPosture) => void;
  onLoadMore?: () => void;
};

export function ExposureAssetTable({ page, loading, onSelect, onViewGraph, onLoadMore }: Props) {
  if (!page?.items.length && !loading) {
    return null;
  }

  return (
    <div className="space-y-2">
      {page?.items.map((asset) => (
        <div
          key={asset.asset_key}
          className="rounded-lg border border-border/60 bg-background/40 p-3 hover:bg-muted/15"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <button
              type="button"
              className="min-w-0 flex-1 text-left"
              onClick={() => onSelect?.(asset)}
            >
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={sevVariant(asset.severity)}>{asset.severity}</Badge>
                <span className="font-mono text-[12px] font-semibold">{asset.risk_score}</span>
                <span className="text-[11px] text-muted-foreground">conf {asset.confidence}%</span>
                <span className="text-[11px] text-muted-foreground">{asset.status}</span>
              </div>
              <div className="mt-1 truncate font-mono text-[12px]" title={asset.asset_key}>
                {asset.display_name}
              </div>
              {asset.hostname && (
                <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{asset.hostname}</div>
              )}
            </button>
            <div className="flex shrink-0 gap-2">
              <Button variant="ghost" size="sm" onClick={() => onViewGraph?.(asset)}>
                Graph
              </Button>
              <Button variant="ghost" size="sm" onClick={() => onSelect?.(asset)}>
                Detail
              </Button>
            </div>
          </div>
        </div>
      ))}

      {loading && (
        <div className="py-2 text-center font-mono text-[11px] text-muted-foreground">Loading…</div>
      )}

      {page?.has_more && !loading && (
        <Button variant="ghost" size="sm" className="w-full" onClick={onLoadMore}>
          Load more
        </Button>
      )}
    </div>
  );
}
