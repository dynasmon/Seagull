import { SeverityPill } from "@/shared/components/SeverityPill";
import type { SeverityVariant } from "@/shared/components/SeverityPill";

function toVariant(sev: string): SeverityVariant {
  const s = String(sev || "").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") {
    return s as SeverityVariant;
  }
  return "neutral";
}

export function SeverityBadge({ severity, withDot = false }: { severity: string; withDot?: boolean }) {
  return (
    <SeverityPill variant={toVariant(severity)} withDot={withDot}>
      {severity || "unknown"}
    </SeverityPill>
  );
}
