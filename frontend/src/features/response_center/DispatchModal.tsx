import { useState } from "react";
import {
  EuiButton,
  EuiButtonEmpty,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
} from "@elastic/eui";

import { Badge } from "@/shared/components/Badge";
import { InlineAlert } from "@/shared/components/InlineAlert";
import { TextArea } from "@/shared/components/TextArea";

import { riskVariant } from "./lib";
import type { ActionTypeOut } from "./types";

interface DispatchModalProps {
  definition: ActionTypeOut;
  targetAgentIds: string[];
  payload: Record<string, any>;
  busy: boolean;
  error: string | null;
  onConfirm: (justification: string) => void;
  onClose: () => void;
}

export default function DispatchModal({ definition, targetAgentIds, payload, busy, error, onConfirm, onClose }: DispatchModalProps) {
  const [justification, setJustification] = useState("");

  const confirmColor: "danger" | "warning" | "primary" =
    definition.risk_level === "critical" || definition.risk_level === "high"
      ? "danger"
      : definition.risk_level === "medium"
        ? "warning"
        : "primary";

  return (
    <EuiModal onClose={onClose} maxWidth={560}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>
          <div className="flex items-center gap-2">
            <span>Confirm: {definition.label}</span>
            <Badge variant={riskVariant(definition.risk_level)}>{definition.risk_level}</Badge>
          </div>
        </EuiModalHeaderTitle>
      </EuiModalHeader>

      <EuiModalBody>
        <div className="space-y-3">
          <div className="text-[12px] text-muted-foreground">{definition.description}</div>

          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Target{targetAgentIds.length === 1 ? "" : "s"} ({targetAgentIds.length})
            </div>
            <div className="mt-1 max-h-24 overflow-y-auto rounded border border-border/60 bg-background/30 p-2 font-mono text-[11px]">
              {targetAgentIds.length ? targetAgentIds.join(", ") : "No agents selected"}
            </div>
          </div>

          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">Payload</div>
            <pre className="mt-1 max-h-48 overflow-auto rounded border border-border/60 bg-background/30 p-2 font-mono text-[11px]">
              {JSON.stringify(payload ?? {}, null, 2)}
            </pre>
          </div>

          {!definition.reversible ? (
            <InlineAlert tone="danger">This action cannot be undone.</InlineAlert>
          ) : null}

          <div>
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">Justification</div>
            <TextArea
              className="mt-1 font-mono text-[11px]"
              rows={3}
              value={justification}
              onChange={(event) => setJustification(event.target.value)}
              placeholder="Reason recorded with the audit trail (optional)"
              disabled={busy}
            />
          </div>

          {error ? <InlineAlert tone="danger">{error}</InlineAlert> : null}
        </div>
      </EuiModalBody>

      <EuiModalFooter>
        <EuiButtonEmpty onClick={onClose} disabled={busy}>
          Cancel
        </EuiButtonEmpty>
        <EuiButton
          fill
          color={confirmColor}
          onClick={() => onConfirm(justification)}
          isLoading={busy}
          disabled={busy || targetAgentIds.length === 0}
        >
          Confirm execution
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
}
