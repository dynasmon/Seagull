import { Badge } from "@/shared/components/Badge";

import { Recommendation } from "../types";
import {
  recommendationPriorityLabel,
  recommendationSafetyLabel,
  sortRecommendations,
} from "../utils";
import { ExposureEvidenceList } from "./ExposureEvidenceList";

type Props = {
  recommendations: Recommendation[];
};

const SAFETY_BADGE: Record<string, "low" | "medium" | "critical" | "info" | "neutral"> = {
  safe: "info",
  caution: "medium",
  destructive: "critical",
};

export function ExposureRecommendationsPanel({ recommendations }: Props) {
  const ordered = sortRecommendations(recommendations);

  if (ordered.length === 0) {
    return <p className="text-xs text-muted-foreground">No backend recommendations are currently attached to this view.</p>;
  }

  return (
    <ol className="space-y-3">
      {ordered.map((rec, index) => (
        <li key={`${rec.action}:${index}`} className="rounded-lg border border-border/60 bg-background/35 p-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={SAFETY_BADGE[rec.safety_level] ?? "neutral"}>
                  {recommendationSafetyLabel(rec.safety_level)}
                </Badge>
                <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
                  Priority {rec.priority} · {recommendationPriorityLabel(rec.priority)}
                </span>
                {rec.requires_admin ? (
                  <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-warning">
                    Admin required
                  </span>
                ) : null}
              </div>
              <div className="mt-2 text-sm font-semibold text-foreground">{rec.title}</div>
              <div className="mt-1 text-sm leading-6 text-muted-foreground">{rec.reason}</div>
              {rec.reason_code ? (
                <div className="mt-2 text-[11px] font-mono text-muted-foreground">
                  Reason code: {rec.reason_code}
                </div>
              ) : null}
              {rec.safety_level !== "safe" ? (
                <div className="mt-2 text-[11px] text-muted-foreground">
                  This recommendation is advisory. Review analyst and change-control requirements before executing any response action.
                </div>
              ) : null}
            </div>
            <div className="shrink-0 text-[11px] font-mono text-muted-foreground">#{index + 1}</div>
          </div>

          {rec.related_evidence_refs.length > 0 ? (
            <div className="mt-3 border-t border-border/50 pt-3">
              <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.16em] text-muted-foreground">
                Related evidence
              </div>
              <ExposureEvidenceList refs={rec.related_evidence_refs} compact />
            </div>
          ) : null}
        </li>
      ))}
    </ol>
  );
}
