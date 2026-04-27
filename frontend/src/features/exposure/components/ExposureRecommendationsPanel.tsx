import { Recommendation } from "../types";

type Props = {
  recommendations: Recommendation[];
};

const SAFETY_COLORS: Record<string, string> = {
  safe: "text-success",
  caution: "text-warning",
  destructive: "text-danger",
};

export function ExposureRecommendationsPanel({ recommendations }: Props) {
  if (!recommendations.length) {
    return <p className="text-xs text-muted-foreground">No recommendations.</p>;
  }
  return (
    <ol className="space-y-3">
      {recommendations.map((rec, i) => (
        <li key={`${rec.action}:${i}`} className="text-xs">
          <div className="flex items-start gap-2">
            <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-muted text-[9px] font-bold text-muted-foreground">
              {i + 1}
            </span>
            <div className="flex-1">
              <div className="font-medium leading-snug">{rec.title}</div>
              <div className="mt-0.5 text-muted-foreground">{rec.reason}</div>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <span className={SAFETY_COLORS[rec.safety_level] ?? "text-muted-foreground"}>
                  {rec.safety_level}
                </span>
                {rec.requires_admin && (
                  <span className="text-[10px] text-warning">admin required</span>
                )}
                {rec.reason_code && (
                  <span className="text-[10px] text-muted-foreground">{rec.reason_code}</span>
                )}
              </div>
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}
