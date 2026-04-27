import { ExposureAttackPathStage } from "../types";

type Props = {
  stages: ExposureAttackPathStage[];
};

const STAGE_COLORS: Record<string, string> = {
  recon: "bg-info/20 text-info border-info/40",
  initial_access: "bg-warning/20 text-warning border-warning/40",
  execution: "bg-warning/20 text-warning border-warning/40",
  persistence: "bg-danger/20 text-danger border-danger/40",
  privilege_escalation: "bg-danger/20 text-danger border-danger/40",
  lateral_movement: "bg-danger/20 text-danger border-danger/40",
  exfiltration: "bg-danger/20 text-danger border-danger/40",
  impact: "bg-danger/20 text-danger border-danger/40",
};

export function ExposureAttackPathTimeline({ stages }: Props) {
  if (!stages.length) {
    return <p className="text-xs text-muted-foreground">No attack path stages.</p>;
  }
  return (
    <ol className="flex flex-wrap gap-2">
      {stages.map((stage, i) => {
        const cls = STAGE_COLORS[stage.stage] ?? "bg-muted/40 text-muted-foreground border-border/60";
        return (
          <li key={`${stage.stage}:${i}`} className="flex items-center gap-1.5">
            {i > 0 && <span className="text-muted-foreground/50">→</span>}
            <span
              className={`inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] ${cls}`}
              title={`Confidence: ${stage.confidence}% · Source: ${stage.source}`}
            >
              {stage.label}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
