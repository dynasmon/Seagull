import { SeverityPill } from "@/shared/components/SeverityPill";

import { ExposureAttackPath } from "../types";
import {
  exposureSeverityVariant,
  formatExposureConfidence,
  formatExposureScore,
  truncateText,
} from "../utils";
import { ExposureEvidenceList } from "./ExposureEvidenceList";
import { ExposureRecommendationsPanel } from "./ExposureRecommendationsPanel";

type Props = {
  path: ExposureAttackPath;
};

const STAGE_CLASSES: Record<string, string> = {
  recon: "border-info/40 bg-info/10 text-info",
  exposure: "border-info/40 bg-info/10 text-info",
  initial_access: "border-warning/40 bg-warning/10 text-warning",
  execution: "border-warning/40 bg-warning/10 text-warning",
  persistence: "border-danger/40 bg-danger/10 text-danger",
  defense_evasion: "border-danger/40 bg-danger/10 text-danger",
  lateral_movement: "border-danger/40 bg-danger/10 text-danger",
  attack_chain: "border-danger/40 bg-danger/10 text-danger",
  exfiltration: "border-danger/40 bg-danger/10 text-danger",
  impact: "border-danger/40 bg-danger/10 text-danger",
};

export function ExposureAttackPathTimeline({ path }: Props) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-foreground">{path.title}</div>
          {path.summary ? <div className="mt-1 text-[12px] leading-6 text-muted-foreground">{path.summary}</div> : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityPill variant={exposureSeverityVariant(path.severity)}>{path.severity}</SeverityPill>
          <span className="rounded-sm border border-border/60 bg-background/40 px-2 py-0.5 font-mono text-[11px] text-foreground">
            {formatExposureScore(path.risk_score)}
          </span>
          <span className="font-mono text-[11px] text-muted-foreground">{formatExposureConfidence(path.confidence)}</span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {path.stages.length > 0 ? (
          path.stages.map((stage, index) => (
            <div key={`${stage.stage}:${index}`} className="flex items-center gap-2">
              {index > 0 ? <span className="text-muted-foreground/60">→</span> : null}
              <span
                className={`inline-flex items-center rounded-sm border px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.08em] ${STAGE_CLASSES[stage.stage] || "border-border/60 bg-muted/20 text-muted-foreground"}`}
                title={`${stage.label} · confidence ${stage.confidence}% · source ${stage.source}`}
              >
                {truncateText(stage.label, 42)}
              </span>
            </div>
          ))
        ) : (
          <span className="text-[12px] text-muted-foreground">No normalized path stages.</span>
        )}
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <div className="rounded-lg border border-border/60 bg-background/30 p-3">
          <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Asset</div>
          <div className="mt-1 break-all font-mono text-[12px] text-foreground">{path.asset_key}</div>
        </div>
        <div className="rounded-lg border border-border/60 bg-background/30 p-3">
          <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Linked graph</div>
          <div className="mt-1 text-sm font-semibold text-foreground">
            {path.nodes.length} nodes · {path.edges.length} edges
          </div>
        </div>
        <div className="rounded-lg border border-border/60 bg-background/30 p-3">
          <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">Evidence refs</div>
          <div className="mt-1 text-sm font-semibold text-foreground">{path.evidence_refs.length}</div>
        </div>
      </div>

      {path.evidence_refs.length > 0 ? (
        <div>
          <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
            Path evidence
          </div>
          <ExposureEvidenceList refs={path.evidence_refs} compact />
        </div>
      ) : null}

      {path.recommendations.length > 0 ? (
        <div>
          <div className="mb-2 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
            Recommended actions
          </div>
          <ExposureRecommendationsPanel recommendations={path.recommendations} />
        </div>
      ) : null}
    </div>
  );
}
