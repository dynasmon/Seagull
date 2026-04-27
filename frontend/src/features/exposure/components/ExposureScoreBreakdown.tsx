import { ScoreBreakdown, ScoreExplanation } from "../types";

type Props = {
  breakdown: ScoreBreakdown;
  explanation?: ScoreExplanation | null;
};

const BREAKDOWN_LABELS: Record<keyof ScoreBreakdown, string> = {
  exposure_score: "Exposure",
  vulnerability_score: "Vulnerability",
  active_threat_score: "Active Threat",
  persistence_score: "Persistence",
  attack_chain_score: "Attack Chain",
  asset_criticality_score: "Asset Criticality",
  reliability_penalty: "Reliability Penalty",
};

export function ExposureScoreBreakdown({ breakdown, explanation }: Props) {
  const keys = Object.keys(BREAKDOWN_LABELS) as Array<keyof ScoreBreakdown>;
  return (
    <div className="space-y-1">
      {explanation && (
        <div className="mb-2 flex items-center gap-2">
          <span className="text-lg font-semibold">{explanation.risk_score}</span>
          <span className="text-xs text-muted-foreground">risk score</span>
          {explanation.confidence_note && (
            <span className="text-[10px] text-muted-foreground">{explanation.confidence_note}</span>
          )}
        </div>
      )}
      {keys.map((k) => {
        const val = breakdown[k];
        if (!val) return null;
        return (
          <div key={k} className="flex items-center justify-between gap-2 text-xs">
            <span className="text-muted-foreground">{BREAKDOWN_LABELS[k]}</span>
            <span className={k === "reliability_penalty" ? "text-danger" : "font-medium"}>
              {k === "reliability_penalty" ? `−${Math.abs(val)}` : `+${val}`}
            </span>
          </div>
        );
      })}
      {explanation?.reasons && explanation.reasons.length > 0 && (
        <div className="mt-2 space-y-1 border-t border-border/40 pt-2">
          {explanation.reasons.map((r) => (
            <div key={r.code} className="text-[11px] text-muted-foreground">
              <span className="font-medium text-foreground">{r.code}:</span> {r.description}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
