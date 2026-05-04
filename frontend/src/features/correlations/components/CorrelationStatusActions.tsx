import { TextArea } from "@/shared/components/TextArea";
import { InlineAlert } from "@/shared/components/InlineAlert";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationSection,
} from "@/shared/components/investigation";

import type { CorrelationLifecycleStatus } from "../types";

const STATUS_ACTIONS: Array<{ key: CorrelationLifecycleStatus; label: string }> = [
  { key: "open", label: "Open" },
  { key: "triaged", label: "Triaged" },
  { key: "closed", label: "Closed" },
  { key: "suppressed", label: "Suppressed" },
];

export default function CorrelationStatusActions({
  currentStatus,
  summary,
  busyStatus,
  error,
  onSummaryChange,
  onChangeStatus,
}: {
  currentStatus: CorrelationLifecycleStatus | string;
  summary: string;
  busyStatus: CorrelationLifecycleStatus | null;
  error?: string | null;
  onSummaryChange: (value: string) => void;
  onChangeStatus: (status: CorrelationLifecycleStatus) => void;
}) {
  return (
    <InvestigationSection
      title="Lifecycle"
      subtitle="Persist analyst triage state and summary on the durable incident record."
    >
      <div className="space-y-3">
        {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}

        <label className="block">
          <div className="mb-1 text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
            Analyst summary
          </div>
          <TextArea
            value={summary}
            onChange={(event) => onSummaryChange(event.target.value)}
            placeholder="Capture what happened, analyst confidence, and the next investigation step."
          />
        </label>

        <InvestigationActionBar>
          {STATUS_ACTIONS.map((item) => (
            <InvestigationActionButton
              key={item.key}
              tone={String(currentStatus) === item.key ? "primary" : "default"}
              disabled={busyStatus !== null}
              onClick={() => onChangeStatus(item.key)}
              title={`Set incident status to ${item.key}`}
            >
              {busyStatus === item.key ? "Saving..." : item.label}
            </InvestigationActionButton>
          ))}
        </InvestigationActionBar>
      </div>
    </InvestigationSection>
  );
}
