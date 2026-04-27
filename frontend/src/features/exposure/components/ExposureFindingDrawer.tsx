import { useState } from "react";

import Drawer from "@/shared/components/Drawer";
import {
  InvestigationChipList,
  InvestigationFactCard,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
} from "@/shared/components/investigation";
import { ExposureFinding, ExposureSeverity } from "../types";
import { ExposureEvidenceList } from "./ExposureEvidenceList";

function sevVariant(s: ExposureSeverity) {
  if (s === "informational") return "info" as const;
  if (s === "unknown") return "neutral" as const;
  return s as "critical" | "high" | "medium" | "low";
}

type Tab = "overview" | "evidence" | "recommendations";

type Props = {
  finding: ExposureFinding | null;
  onClose: () => void;
};

export function ExposureFindingDrawer({ finding, onClose }: Props) {
  const [tab, setTab] = useState<Tab>("overview");
  const f = finding;

  return (
    <Drawer
      open={f !== null}
      title={f?.title ?? "Finding"}
      description={
        f
          ? `${f.finding_key} · ${f.asset_key} · Last seen ${new Date(f.last_seen_at).toLocaleString()}`
          : ""
      }
      onClose={() => {
        setTab("overview");
        onClose();
      }}
      widthClassName="w-[640px]"
      headerLabel="Exposure Finding"
    >
      {f && (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Severity", value: f.severity, variant: sevVariant(f.severity) },
              { label: "Status", value: f.status },
              { label: "Type", value: f.finding_type },
              { label: "Confidence", value: `${f.confidence}%` },
              { label: "Score delta", value: `+${f.score_delta}` },
            ]}
          />

          <InvestigationTabs
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "evidence", label: "Evidence" },
              { key: "recommendations", label: "Actions" },
            ]}
          />

          {tab === "overview" && (
            <>
              <InvestigationSection title="Finding details">
                <InvestigationSummaryGrid>
                  <InvestigationFactCard label="Finding key" value={f.finding_key} mono copyValue={f.finding_key} />
                  <InvestigationFactCard label="Asset" value={f.asset_key} mono copyValue={f.asset_key} />
                  <InvestigationFactCard label="Finding type" value={f.finding_type} mono />
                  <InvestigationFactCard label="Status" value={f.status} mono />
                  <InvestigationFactCard label="Score delta" value={`+${f.score_delta}`} mono />
                  <InvestigationFactCard label="Confidence" value={`${f.confidence}%`} mono />
                  <InvestigationFactCard label="First seen" value={new Date(f.first_seen_at).toLocaleString()} mono />
                  <InvestigationFactCard label="Last seen" value={new Date(f.last_seen_at).toLocaleString()} mono />
                </InvestigationSummaryGrid>
              </InvestigationSection>

              {f.summary && (
                <InvestigationSection title="Summary">
                  <div className="text-sm leading-6 text-foreground/90">{f.summary}</div>
                </InvestigationSection>
              )}

              {f.reason_codes.length > 0 && (
                <InvestigationChipList
                  title="Reason codes"
                  chips={f.reason_codes.map((c) => ({ label: c, variant: "neutral" as const }))}
                />
              )}
            </>
          )}

          {tab === "evidence" && (
            <InvestigationSection title="Evidence references">
              <ExposureEvidenceList refs={f.evidence_refs} />
            </InvestigationSection>
          )}

          {tab === "recommendations" && (
            <InvestigationSection title="Recommendations">
              {f.recommendations.length === 0 ? (
                <p className="text-sm text-muted-foreground">No recommendations.</p>
              ) : (
                <ol className="space-y-3">
                  {f.recommendations.map((rec, i) => (
                    <li key={`${rec.action}:${i}`} className="rounded-lg border border-border/60 bg-background/35 p-3">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                        Priority {rec.priority} · {rec.safety_level}
                        {rec.requires_admin && " · admin required"}
                      </div>
                      <div className="mt-1 text-sm font-semibold">{rec.title}</div>
                      <div className="mt-1 text-sm text-muted-foreground">{rec.reason}</div>
                    </li>
                  ))}
                </ol>
              )}
            </InvestigationSection>
          )}
        </InvestigationShell>
      )}
    </Drawer>
  );
}
