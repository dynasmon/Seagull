import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import {
  InvestigationChipList,
  InvestigationFactCard,
  InvestigationFieldGroup,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import { eventSeverity } from "../lib";
import type { AuditEvent } from "../types";

export default function AuditEventDrawer({ event, onClose }: { event: AuditEvent | null; onClose: () => void }) {
  const sev = event ? eventSeverity(event) : "neutral";

  return (
    <Drawer
      open={Boolean(event)}
      onClose={onClose}
      title={event ? `Audit event #${event.id}` : "Audit event"}
      description={event ? `${event.event_type} · ${event.action} · ${formatInvestigationTimestamp(event.created_at)}` : ""}
      widthClassName="w-[940px]"
      headerLabel="Audit"
    >
      {!event ? null : (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Category", value: event.event_type, variant: "info" },
              { label: "Action", value: event.action },
              { label: "Outcome", value: event.outcome || "-", variant: sev },
              { label: "Recorded", value: formatInvestigationTimestamp(event.created_at) },
              { label: "Actor", value: event.actor_username || "-" },
              { label: "Resource", value: event.resource_type || "-" },
            ]}
          />

          <InvestigationSection title="Audit summary" subtitle="Primary actor, target, request, and severity context.">
            <InvestigationSummaryGrid className="xl:grid-cols-4">
              <InvestigationFactCard label="Event ID" value={`#${event.id}`} mono copyValue={String(event.id)} />
              <InvestigationFactCard label="Severity" value={<Badge variant={sev}>severity {sev}</Badge>} />
              <InvestigationFactCard label="Actor username" value={event.actor_username || "-"} mono />
              <InvestigationFactCard label="Actor user ID" value={event.actor_user_id ?? "-"} mono />
              <InvestigationFactCard label="Origin IP" value={event.ip || "-"} mono />
              <InvestigationFactCard label="Resource type" value={event.resource_type || "-"} mono />
              <InvestigationFactCard label="Resource ID" value={event.resource_id || "-"} mono copyValue={event.resource_id || null} />
              <InvestigationFactCard label="When" value={formatInvestigationTimestamp(event.created_at)} mono />
            </InvestigationSummaryGrid>
          </InvestigationSection>

          <InvestigationSection title="Actor and request" subtitle="Origin metadata and request correlation preserved from backend audit evidence.">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <InvestigationFieldGroup
                title="Actor / origin"
                entries={[
                  { key: "username", value: event.actor_username || "-" },
                  { key: "user_id", value: String(event.actor_user_id ?? "-") },
                  { key: "ip", value: event.ip || "-" },
                  { key: "user_agent", value: event.user_agent || "-" },
                ]}
              />
              <InvestigationFieldGroup
                title="Request metadata"
                entries={[
                  { key: "method", value: event.method || "-" },
                  { key: "path", value: event.path || "-" },
                  { key: "request_id", value: event.request_id || "-" },
                  { key: "trace_id", value: event.trace_id || "-" },
                  { key: "operation_id", value: event.operation_id || "-" },
                ]}
              />
            </div>
          </InvestigationSection>

          <InvestigationSection title="Change evidence" subtitle="Field-level diffs, integrity hashes, and backend-supplied reason/error values.">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <InvestigationFieldGroup
                title="Resource context"
                entries={[
                  { key: "reason", value: event.reason || "-" },
                  { key: "error", value: event.error || "-" },
                  { key: "resource_type", value: event.resource_type || "-" },
                  { key: "resource_id", value: event.resource_id || "-" },
                ]}
              />
              <InvestigationFieldGroup
                title="Integrity chain"
                entries={[
                  { key: "event_hash", value: event.event_hash || "-" },
                  { key: "prev_event_hash", value: event.prev_event_hash || "-" },
                ]}
                emptyHint="Integrity data was not attached to this event."
              />
            </div>

            <div className="mt-4">
              <InvestigationChipList
                title="Changed fields"
                chips={
                  event.changed_fields?.length
                    ? event.changed_fields.map((field) => ({ label: field, variant: "neutral" as const }))
                    : [{ label: "No field-level diff metadata.", variant: "neutral" as const }]
                }
              />
            </div>

            <div className="mt-4 text-[11px] text-muted-foreground">
              Redacted fields are preserved exactly as provided by the backend and are not reconstructed in the frontend.
            </div>
          </InvestigationSection>

          <InvestigationRawJsonPanel value={event.before} title="Before (redacted JSON)" />
          <InvestigationRawJsonPanel value={event.after} title="After (redacted JSON)" />
          <InvestigationRawJsonPanel value={event.context} title="Context JSON" />
        </InvestigationShell>
      )}
    </Drawer>
  );
}
