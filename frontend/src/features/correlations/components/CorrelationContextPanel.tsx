import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  InvestigationFactCard,
  InvestigationSection,
  InvestigationSummaryGrid,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import type { CorrelationContext } from "../types";
import { correlationEntityLabel } from "./correlationUtils";

type ContextIncident = {
  correlation_rule_name: string;
  correlation_rule_id?: number | null;
  entity_type?: string | null;
  entity_value?: string | null;
  group_by: string;
  group_value: string;
  dedup_key?: string;
  started_at: string;
  last_seen_at?: string;
  ended_at?: string;
  closed_at?: string | null;
  alert_count: number;
  unique_rules: string[];
  summary?: string | null;
  context?: CorrelationContext;
};

export default function CorrelationContextPanel({
  incident,
}: {
  incident: ContextIncident | null;
}) {
  if (!incident) return null;

  const entity = correlationEntityLabel(
    incident.entity_type ?? null,
    incident.entity_value ?? null,
    incident.group_by,
    incident.group_value,
  );
  const lastSeenAt = incident.last_seen_at || incident.ended_at || incident.started_at;

  return (
    <InvestigationSection
      title="Incident context"
      subtitle={incident.summary || "Persisted entity context, dedup identity, and correlation metadata."}
    >
      <div className="space-y-4">
        {incident.summary ? (
          <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-3 text-sm text-foreground">
            {incident.summary}
          </div>
        ) : null}

        <InvestigationSummaryGrid>
          <InvestigationFactCard label="Rule" value={incident.correlation_rule_name} mono />
          <InvestigationFactCard label="Entity" value={entity.value} hint={entity.type} mono copyValue={entity.value} />
          <InvestigationFactCard label="Group" value={incident.group_value} hint={incident.group_by} mono copyValue={incident.group_value} />
          <InvestigationFactCard label="Started" value={formatInvestigationTimestamp(incident.started_at)} mono />
          <InvestigationFactCard label="Last seen" value={formatInvestigationTimestamp(lastSeenAt)} mono />
          <InvestigationFactCard label="Closed" value={formatInvestigationTimestamp(incident.closed_at)} mono />
          <InvestigationFactCard label="Alerts" value={incident.alert_count} />
          <InvestigationFactCard label="Unique rules" value={incident.unique_rules.length} />
          <InvestigationFactCard label="Dedup key" value={incident.dedup_key || "-"} mono copyValue={incident.dedup_key || undefined} />
        </InvestigationSummaryGrid>

        <div className="space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-[0.35em] text-muted-foreground">Context JSON</div>
          <JsonBlock value={incident.context || {}} showControls={false} />
        </div>
      </div>
    </InvestigationSection>
  );
}
