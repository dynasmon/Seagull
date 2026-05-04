import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  InvestigationFieldGroup,
  InvestigationListItem,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import type { CorrelationEvidence } from "../types";
import {
  correlationEvidenceDescription,
  correlationEvidenceTitle,
} from "./correlationUtils";

function compactNetwork(value?: string | null, port?: number | null) {
  if (!value) return port ? `:${port}` : "-";
  return port ? `${value}:${port}` : value;
}

export default function CorrelationEvidenceList({
  evidence,
}: {
  evidence: CorrelationEvidence[];
}) {
  if (evidence.length === 0) {
    return (
      <div className="rounded-lg border border-border/60 bg-background/25 px-3 py-2 text-sm text-muted-foreground">
        No persisted evidence items are attached to this incident.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {evidence.map((item, index) => {
        const details = item.details || {};
        return (
          <InvestigationListItem
            key={`${item.id ?? item.timestamp}-${item.alert_id ?? "na"}-${item.net_event_id ?? "na"}-${index}`}
            title={correlationEvidenceTitle(item)}
            description={correlationEvidenceDescription(item)}
            badges={[
              { label: item.evidence_type, variant: "neutral" as const },
              item.stage ? { label: item.stage, variant: "info" as const } : null,
              item.rule_id ? { label: item.rule_id, variant: "low" as const } : null,
            ].filter(Boolean) as Array<{ label: string; variant?: "neutral" | "info" | "low" }>}
            meta={[
              { label: "when", value: formatInvestigationTimestamp(item.timestamp) },
              item.alert_id ? { label: "alert", value: item.alert_id } : null,
              item.net_event_id ? { label: "event", value: item.net_event_id } : null,
            ].filter(Boolean) as Array<{ label?: string; value: string | number }>}
          >
            <div className="grid gap-3 xl:grid-cols-2">
              <InvestigationFieldGroup
                title="Network"
                entries={[
                  { key: "src_ip", value: item.src_ip || "-" },
                  { key: "dst_ip", value: compactNetwork(item.dst_ip, item.dst_port) },
                  { key: "rule_id", value: item.rule_id || "-" },
                  { key: "stage", value: item.stage || "-" },
                ]}
              />
              <InvestigationFieldGroup
                title="Context"
                entries={[
                  { key: "event_type", value: String(details.event_type || "-") },
                  { key: "agent_id", value: String(details.agent_id || "-") },
                  { key: "finding_key", value: String(details.finding_key || "-") },
                  { key: "technique_id", value: String(details.technique_id || "-") },
                ]}
              />
            </div>

            {Object.keys(details).length > 0 ? (
              <div className="mt-3">
                <JsonBlock value={details} showControls={false} maxHeight="220px" />
              </div>
            ) : null}
          </InvestigationListItem>
        );
      })}
    </div>
  );
}
