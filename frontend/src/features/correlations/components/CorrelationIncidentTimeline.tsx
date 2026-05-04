import { useMemo } from "react";

import {
  InvestigationListItem,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import type { CorrelationEvidence } from "../types";
import { correlationEvidenceDescription, correlationEvidenceTitle } from "./correlationUtils";

function evidenceTone(value: string) {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "alert") return "high";
  if (normalized === "net_event") return "info";
  if (normalized === "attack_chain_step") return "medium";
  if (normalized === "vulnerability") return "low";
  return "neutral";
}

export default function CorrelationIncidentTimeline({
  evidence,
}: {
  evidence: CorrelationEvidence[];
}) {
  const ordered = useMemo(
    () => [...evidence].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()),
    [evidence],
  );

  if (ordered.length === 0) {
    return (
      <div className="rounded-lg border border-border/60 bg-background/25 px-3 py-2 text-sm text-muted-foreground">
        No timeline entries are available yet.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {ordered.map((item, index) => (
        <div key={`${item.id ?? item.timestamp}-${index}`} className="relative pl-6">
          <span className="absolute left-[7px] top-5 h-full w-px bg-border/60" aria-hidden="true" />
          <span className="absolute left-0 top-[18px] h-3.5 w-3.5 rounded-full border border-primary/40 bg-background" aria-hidden="true" />
          <InvestigationListItem
            title={correlationEvidenceTitle(item)}
            description={correlationEvidenceDescription(item)}
            badges={[
              { label: item.evidence_type, variant: evidenceTone(item.evidence_type) as "high" | "medium" | "info" | "low" | "neutral" },
              item.stage ? { label: item.stage, variant: "info" as const } : null,
            ].filter(Boolean) as Array<{ label: string; variant?: "high" | "medium" | "info" | "low" | "neutral" }>}
            meta={[
              { label: "when", value: formatInvestigationTimestamp(item.timestamp) },
              item.src_ip ? { label: "src", value: item.src_ip } : null,
              item.dst_ip ? { label: "dst", value: item.dst_port ? `${item.dst_ip}:${item.dst_port}` : item.dst_ip } : null,
            ].filter(Boolean) as Array<{ label?: string; value: string }>}
          />
        </div>
      ))}
    </div>
  );
}
