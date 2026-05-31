export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info" | "neutral";

export const severityClasses: Record<SeverityLevel, string> = {
  critical: "text-severity-critical border-severity-critical bg-severity-critical/10",
  high: "text-severity-high border-severity-high bg-severity-high/10",
  medium: "text-severity-medium border-severity-medium bg-severity-medium/10",
  low: "text-severity-low border-severity-low bg-severity-low/10",
  info: "text-info border-info/45 bg-info/10",
  neutral: "text-muted-foreground border-border/60 bg-muted/10",
};

export function severityBadgeClasses(severity: string): string {
  const s = (severity || "").toLowerCase() as SeverityLevel;
  return severityClasses[s] ?? severityClasses.neutral;
}

export function riskScoreClasses(score: number): string {
  if (score >= 80) return "border-severity-critical/50 text-severity-critical";
  if (score >= 65) return "border-severity-high/50 text-severity-high";
  return "border-border/60 text-foreground";
}

export const severityEuiColor: Record<SeverityLevel, string> = {
  critical: "danger",
  high: "#E8730C",
  medium: "warning",
  low: "primary",
  info: "primary",
  neutral: "hollow",
};
