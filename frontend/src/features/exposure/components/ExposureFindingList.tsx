import { Badge } from "@/shared/components/Badge";
import { Button } from "@/shared/components/Button";
import { CursorPage } from "@/shared/types/pagination";
import { ExposureFinding, ExposureSeverity } from "../types";

function sevVariant(s: ExposureSeverity) {
  if (s === "informational") return "info" as const;
  if (s === "unknown") return "neutral" as const;
  return s as "critical" | "high" | "medium" | "low";
}

type Props = {
  page: CursorPage<ExposureFinding> | null;
  loading?: boolean;
  onSelect?: (finding: ExposureFinding) => void;
  onLoadMore?: () => void;
};

export function ExposureFindingList({ page, loading, onSelect, onLoadMore }: Props) {
  if (!page?.items.length && !loading) return null;

  return (
    <div className="space-y-2">
      {page?.items.map((f) => (
        <button
          key={f.finding_key}
          type="button"
          className="w-full rounded-lg border border-border/60 bg-background/40 p-3 text-left hover:bg-muted/15"
          onClick={() => onSelect?.(f)}
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={sevVariant(f.severity)}>{f.severity}</Badge>
                {f.score_delta > 0 && (
                  <span className="font-mono text-[11px] text-danger">+{f.score_delta}</span>
                )}
                <span className="text-[11px] text-muted-foreground">{f.finding_type}</span>
                <span className="text-[11px] text-muted-foreground">{f.status}</span>
              </div>
              <div className="mt-1 font-mono text-[12px]">{f.title}</div>
              {f.summary && (
                <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{f.summary}</div>
              )}
            </div>
          </div>
        </button>
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
