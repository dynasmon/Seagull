import { JsonBlock } from "@/shared/components/JsonBlock";

import { EvidenceRef } from "../types";
import {
  boundedMetadataEntries,
  exposureEvidenceTypeLabel,
  formatExposureTimestamp,
  truncateText,
} from "../utils";

type Props = {
  refs: EvidenceRef[];
  compact?: boolean;
};

export function ExposureEvidenceList({ refs, compact = false }: Props) {
  if (!refs.length) {
    return <p className="text-xs text-muted-foreground">No evidence references.</p>;
  }

  return (
    <ul className="space-y-3">
      {refs.map((ref, index) => {
        const metadataEntries = boundedMetadataEntries(ref);
        return (
          <li key={`${ref.source_type}:${ref.source_id}:${index}`} className="rounded-lg border border-border/60 bg-background/30 p-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-sm border border-border/60 bg-muted/25 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                    {exposureEvidenceTypeLabel(ref.source_type)}
                  </span>
                  <span className="font-mono text-[11px] text-muted-foreground">{ref.source_id}</span>
                </div>
                <div className="mt-2 text-sm font-medium text-foreground">
                  {ref.title || truncateText(ref.summary, compact ? 72 : 120) || ref.source_id}
                </div>
                {ref.summary ? (
                  <div className="mt-1 text-[12px] leading-6 text-muted-foreground">
                    {compact ? truncateText(ref.summary, 140) : ref.summary}
                  </div>
                ) : null}
              </div>
              <div className="shrink-0 text-[11px] font-mono text-muted-foreground">
                {formatExposureTimestamp(ref.observed_at)}
              </div>
            </div>

            {metadataEntries.length > 0 ? (
              <div className="mt-3 border-t border-border/50 pt-3">
                <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                  Metadata
                </div>
                {metadataEntries.length <= 3 && metadataEntries.every((entry) => typeof entry.value !== "object") ? (
                  <div className="grid gap-2 md:grid-cols-2">
                    {metadataEntries.map((entry) => (
                      <div key={entry.key} className="rounded-md border border-border/50 bg-background/35 px-2.5 py-2">
                        <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                          {entry.key}
                        </div>
                        <div className="mt-1 break-words font-mono text-[11px] text-foreground">
                          {String(entry.value)}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <JsonBlock
                    value={Object.fromEntries(metadataEntries.map((entry) => [entry.key, entry.value]))}
                    maxHeight="220px"
                    showControls={false}
                  />
                )}
              </div>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
