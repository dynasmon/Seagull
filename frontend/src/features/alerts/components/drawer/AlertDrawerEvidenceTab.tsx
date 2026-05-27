import { JsonBlock } from "@/shared/components/JsonBlock";
import {
  InvestigationKeyValueGrid,
  InvestigationSection,
} from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

import { toDetailEntries, toDetailNested } from "../../lib/alertPresenters";
import type { Alert, AlertEvidenceItem } from "../../types";

interface AlertDrawerEvidenceTabProps {
  selected: Alert;
  evidenceItems: AlertEvidenceItem[];
  evidenceLoading: boolean;
}

export function AlertDrawerEvidenceTab({ selected, evidenceItems, evidenceLoading }: AlertDrawerEvidenceTabProps) {
  return (
    <InvestigationSection
      title="Evidence"
      subtitle="Rule provenance and structured evidence items that triggered this alert."
    >
      <div className="space-y-4">
        {selected.detector_type || selected.rule_version != null || selected.rule_hash ? (
          <div className="rounded-lg border border-border/60 bg-muted/20 px-3 py-2 space-y-1">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">
              Rule provenance
            </div>
            <InvestigationKeyValueGrid
              entries={[
                selected.detector_type ? { key: "detector_type", value: selected.detector_type } : null,
                selected.rule_version != null ? { key: "rule_version", value: String(selected.rule_version) } : null,
                selected.rule_hash ? { key: "rule_hash", value: selected.rule_hash } : null,
                selected.ruleset_version ? { key: "ruleset_version", value: selected.ruleset_version } : null,
              ].filter((x): x is { key: string; value: string } => x !== null)}
            />
          </div>
        ) : null}

        {evidenceLoading ? (
          <div className="text-xs text-muted-foreground py-2">Loading evidence…</div>
        ) : evidenceItems.length > 0 ? (
          <div className="space-y-2">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Evidence items</div>
            {evidenceItems.map((ev) => (
              <div
                key={ev.id}
                className="rounded-lg border border-border/60 bg-background/35 px-3 py-2 space-y-1"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-[11px] text-foreground">{ev.evidence_type}</span>
                  <span
                    className={cx(
                      "text-[10px] rounded px-1.5 py-0.5",
                      ev.evidence_role === "trigger"
                        ? "bg-orange-500/15 text-orange-400"
                        : "bg-muted text-muted-foreground",
                    )}
                  >
                    {ev.evidence_role}
                  </span>
                  {ev.entity_type && (
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {ev.entity_type}={ev.entity_value ?? "-"}
                    </span>
                  )}
                </div>
                {ev.matched_field && (
                  <div className="font-mono text-[11px]">
                    <span className="text-muted-foreground">{ev.matched_field}: </span>
                    <span className="text-foreground">{ev.matched_value ?? "-"}</span>
                  </div>
                )}
                {ev.summary && <div className="text-xs text-muted-foreground">{ev.summary}</div>}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-xs text-muted-foreground py-1">No structured evidence items for this alert.</div>
        )}

        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
            Detection details
          </div>
          <InvestigationKeyValueGrid
            entries={toDetailEntries(selected.details).map((x) => ({ key: x.key, value: x.value }))}
          />
          {toDetailNested(selected.details).map((block) => (
            <div key={block.key} className="rounded-lg border border-border/60 bg-background/35 p-3 mt-2">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{block.key}</div>
              <JsonBlock value={block.value} maxHeight="220px" showControls={false} className="mt-2" />
            </div>
          ))}
        </div>
      </div>
    </InvestigationSection>
  );
}
