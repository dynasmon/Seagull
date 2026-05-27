import { Button } from "@/shared/components/Button";
import { TextInput } from "@/shared/components/TextInput";
import { InvestigationSection } from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

import { fmtTs } from "../../lib/alertFormatters";
import type { Alert, AlertDisposition, AlertStatus } from "../../types";

interface AlertDrawerTriageTabProps {
  selected: Alert;
  triaging: boolean;
  triageError: string | null;
  triageNotes: string;
  setTriageNotes: (v: string) => void;
  triageAssignedTo: string;
  setTriageAssignedTo: (v: string) => void;
  triagePriority: string;
  setTriagePriority: (v: string) => void;
  triageRiskScore: string;
  setTriageRiskScore: (v: string) => void;
  triageCloseDisposition: AlertDisposition | "";
  setTriageCloseDisposition: (v: AlertDisposition | "") => void;
  onStatusAction: (status: AlertStatus) => void;
  onCloseAction: () => void;
  onSaveFields: () => void;
}

export function AlertDrawerTriageTab({
  selected,
  triaging,
  triageError,
  triageNotes,
  setTriageNotes,
  triageAssignedTo,
  setTriageAssignedTo,
  triagePriority,
  setTriagePriority,
  triageRiskScore,
  setTriageRiskScore,
  triageCloseDisposition,
  setTriageCloseDisposition,
  onStatusAction,
  onCloseAction,
  onSaveFields,
}: AlertDrawerTriageTabProps) {
  return (
    <InvestigationSection title="Triage" subtitle="Manage alert status, disposition, and analyst notes.">
      <div className="space-y-5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground w-20 shrink-0">
            Status
          </div>
          <span
            className={cx(
              "inline-flex items-center rounded-md px-2.5 py-0.5 text-xs font-semibold",
              selected.status === "open" && "bg-blue-500/15 text-blue-400",
              selected.status === "acknowledged" && "bg-yellow-500/15 text-yellow-400",
              selected.status === "investigating" && "bg-orange-500/15 text-orange-400",
              selected.status === "closed" && "bg-muted text-muted-foreground",
            )}
          >
            {selected.status ?? "open"}
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          {(selected.status === "open" || selected.status === "acknowledged") && (
            <Button
              variant="subtle"
              size="sm"
              disabled={triaging}
              onClick={() => onStatusAction("acknowledged" as AlertStatus)}
            >
              Acknowledge
            </Button>
          )}
          {(selected.status === "open" || selected.status === "acknowledged") && (
            <Button
              variant="subtle"
              size="sm"
              disabled={triaging}
              onClick={() => onStatusAction("investigating" as AlertStatus)}
            >
              Investigate
            </Button>
          )}
          {selected.status !== "closed" && (
            <div className="flex items-center gap-2">
              <select
                value={triageCloseDisposition}
                onChange={(e) => setTriageCloseDisposition(e.target.value as AlertDisposition | "")}
                className="h-8 rounded-md border border-border/60 bg-background px-2 text-xs text-foreground"
                aria-label="Disposition for close"
              >
                <option value="">Select disposition…</option>
                <option value="true_positive">True positive</option>
                <option value="false_positive">False positive</option>
                <option value="benign">Benign</option>
                <option value="duplicate">Duplicate</option>
                <option value="expected_activity">Expected activity</option>
                <option value="unknown">Unknown</option>
              </select>
              <Button
                variant="subtle"
                size="sm"
                disabled={triaging || !triageCloseDisposition}
                onClick={onCloseAction}
              >
                Close
              </Button>
            </div>
          )}
          {selected.status === "closed" && (
            <Button
              variant="subtle"
              size="sm"
              disabled={triaging}
              onClick={() => onStatusAction("open" as AlertStatus)}
            >
              Reopen
            </Button>
          )}
        </div>

        {triageError && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {triageError}
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Priority (1–4)
            </label>
            <TextInput
              value={triagePriority}
              onChange={(e) => setTriagePriority(e.target.value)}
              placeholder="1–4"
              className="h-8 w-full"
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Risk score (0–100)
            </label>
            <TextInput
              value={triageRiskScore}
              onChange={(e) => setTriageRiskScore(e.target.value)}
              placeholder="0–100"
              className="h-8 w-full"
            />
          </div>
          <div className="space-y-1.5 col-span-2">
            <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Assigned to
            </label>
            <TextInput
              value={triageAssignedTo}
              onChange={(e) => setTriageAssignedTo(e.target.value)}
              placeholder="analyst username"
              className="h-8 w-full"
            />
          </div>
          <div className="space-y-1.5 col-span-2">
            <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Notes</label>
            <textarea
              value={triageNotes}
              onChange={(e) => setTriageNotes(e.target.value)}
              rows={4}
              placeholder="Analyst notes…"
              className="w-full rounded-md border border-border/60 bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring resize-none"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <Button variant="primary" size="sm" disabled={triaging} onClick={onSaveFields}>
            {triaging ? "Saving…" : "Save fields"}
          </Button>
        </div>

        {(selected.acknowledged_at || selected.closed_at) && (
          <div className="rounded-lg border border-border/60 bg-muted/20 px-3 py-2 space-y-1">
            {selected.acknowledged_at && (
              <div className="text-xs text-muted-foreground">
                Acknowledged {fmtTs(selected.acknowledged_at)}
                {selected.acknowledged_by ? ` by ${selected.acknowledged_by}` : ""}
              </div>
            )}
            {selected.closed_at && (
              <div className="text-xs text-muted-foreground">
                Closed {fmtTs(selected.closed_at)}
                {selected.closed_by ? ` by ${selected.closed_by}` : ""}
                {selected.disposition ? ` · ${selected.disposition.replace(/_/g, " ")}` : ""}
              </div>
            )}
          </div>
        )}
      </div>
    </InvestigationSection>
  );
}
