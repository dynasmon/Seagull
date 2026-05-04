import { useMemo } from "react";

import {
  InvestigationChipList,
  InvestigationSection,
} from "@/shared/components/investigation";

import type {
  CorrelationIncidentDetail,
  CorrelationRunIncident,
} from "../types";
import {
  extractCorrelationMitreMetadata,
  hasCorrelationMitreMetadata,
} from "./correlationUtils";

type MitreSource =
  | Pick<CorrelationIncidentDetail, "context" | "evidence">
  | Pick<CorrelationRunIncident, "context" | "evidence_items">
  | null
  | undefined;

export default function CorrelationMitrePanel({
  incident,
}: {
  incident: MitreSource;
}) {
  const metadata = useMemo(() => extractCorrelationMitreMetadata(incident), [incident]);

  return (
    <InvestigationSection
      title="MITRE context"
      subtitle="ATT&CK tactics and techniques inferred from persisted incident context and evidence."
    >
      {hasCorrelationMitreMetadata(metadata) ? (
        <div className="space-y-4">
          <InvestigationChipList
            title="Tactics"
            chips={metadata.tactics.map((item) => ({ label: item, variant: "neutral" as const }))}
          />
          <InvestigationChipList
            title="Techniques"
            chips={metadata.techniques.map((item) => ({
              label: item.name ? `${item.id} · ${item.name}` : item.id,
              variant: "info" as const,
            }))}
          />
        </div>
      ) : (
        <div className="rounded-lg border border-border/60 bg-background/25 px-3 py-2 text-sm text-muted-foreground">
          No ATT&CK metadata was persisted for this incident yet.
        </div>
      )}
    </InvestigationSection>
  );
}
