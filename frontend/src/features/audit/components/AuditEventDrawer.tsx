import Drawer from "@/shared/components/Drawer";
import { Badge } from "@/shared/components/Badge";
import { Card } from "@/shared/components/Card";

import { eventSeverity, fmtDateTime } from "../lib";
import type { AuditEvent } from "../types";

function safeJson(v: unknown): string {
  try {
    return JSON.stringify(v ?? {}, null, 2);
  } catch {
    return "{}";
  }
}

export default function AuditEventDrawer({ event, onClose }: { event: AuditEvent | null; onClose: () => void }) {
  const sev = event ? eventSeverity(event) : "neutral";

  return (
    <Drawer
      open={Boolean(event)}
      onClose={onClose}
      title={event ? `Audit Event ${event.id}` : "Audit Event"}
      description={event ? `${event.event_type} · ${event.action} · ${fmtDateTime(event.created_at)}` : ""}
      widthClassName="w-[900px]"
    >
      {!event ? null : (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Card title="Event">
              <div className="space-y-1 text-sm">
                <div><span className="text-muted-foreground">Category:</span> {event.event_type}</div>
                <div><span className="text-muted-foreground">Action:</span> {event.action}</div>
                <div><span className="text-muted-foreground">Outcome:</span> {event.outcome}</div>
                <div><span className="text-muted-foreground">When:</span> {fmtDateTime(event.created_at)}</div>
                <div className="pt-1"><Badge variant={sev}>severity: {sev}</Badge></div>
              </div>
            </Card>

            <Card title="Actor / Origin">
              <div className="space-y-1 text-sm">
                <div><span className="text-muted-foreground">Username:</span> {event.actor_username || "-"}</div>
                <div><span className="text-muted-foreground">User id:</span> {event.actor_user_id ?? "-"}</div>
                <div><span className="text-muted-foreground">IP:</span> {event.ip || "-"}</div>
                <div className="break-all"><span className="text-muted-foreground">User agent:</span> {event.user_agent || "-"}</div>
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Card title="Resource">
              <div className="space-y-1 text-sm">
                <div><span className="text-muted-foreground">Type:</span> {event.resource_type}</div>
                <div className="break-all"><span className="text-muted-foreground">Resource id:</span> {event.resource_id || "-"}</div>
                <div><span className="text-muted-foreground">Reason:</span> {event.reason || "-"}</div>
                <div><span className="text-muted-foreground">Error:</span> {event.error || "-"}</div>
              </div>
            </Card>

            <Card title="Request Metadata">
              <div className="space-y-1 text-sm">
                <div><span className="text-muted-foreground">Method:</span> {event.method || "-"}</div>
                <div className="break-all"><span className="text-muted-foreground">Path:</span> {event.path || "-"}</div>
                <div className="break-all"><span className="text-muted-foreground">Request id:</span> {event.request_id || "-"}</div>
                <div className="break-all"><span className="text-muted-foreground">Trace id:</span> {event.trace_id || "-"}</div>
                <div className="break-all"><span className="text-muted-foreground">Operation id:</span> {event.operation_id || "-"}</div>
              </div>
            </Card>
          </div>

          <Card title="Changed Fields">
            <div className="flex flex-wrap gap-2">
              {event.changed_fields && event.changed_fields.length > 0 ? (
                event.changed_fields.map((f) => (
                  <Badge key={f} variant="neutral">
                    {f}
                  </Badge>
                ))
              ) : (
                <div className="text-sm text-muted-foreground">No field-level diff metadata.</div>
              )}
            </div>
          </Card>

          <Card title="Integrity Chain">
            <div className="space-y-1 text-sm">
              <div className="break-all"><span className="text-muted-foreground">event_hash:</span> {event.event_hash || "-"}</div>
              <div className="break-all"><span className="text-muted-foreground">prev_event_hash:</span> {event.prev_event_hash || "-"}</div>
              <div className="text-xs text-muted-foreground">
                Redacted fields are preserved as provided by backend and are not reconstructed in UI.
              </div>
            </div>
          </Card>

          <Card title="Before (redacted JSON)">
            <pre className="max-h-[220px] overflow-auto text-xs leading-relaxed">{safeJson(event.before)}</pre>
          </Card>

          <Card title="After (redacted JSON)">
            <pre className="max-h-[220px] overflow-auto text-xs leading-relaxed">{safeJson(event.after)}</pre>
          </Card>

          <Card title="Context (JSON)">
            <pre className="max-h-[220px] overflow-auto text-xs leading-relaxed">{safeJson(event.context)}</pre>
          </Card>
        </div>
      )}
    </Drawer>
  );
}
