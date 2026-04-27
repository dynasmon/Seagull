import { useMemo, useState } from "react";

import Drawer from "@/shared/components/Drawer";
import {
  InvestigationChipList,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
  InvestigationFactCard,
} from "@/shared/components/investigation";

import { ExposureFinding } from "../types";
import {
  exposureSeverityVariant,
  formatExposureConfidence,
  formatExposureTimestamp,
} from "../utils";
import { ExposureEvidenceList } from "./ExposureEvidenceList";
import { ExposureRecommendationsPanel } from "./ExposureRecommendationsPanel";

type Tab = "overview" | "evidence" | "recommendations";

type Props = {
  finding: ExposureFinding | null;
  onClose: () => void;
};

export function ExposureFindingDrawer({ finding, onClose }: Props) {
  const [tab, setTab] = useState<Tab>("overview");
  const selected = finding;

  const relatedNodeSummary = useMemo(
    () => (selected?.related_node_keys.length ? selected.related_node_keys.join(" · ") : "No related graph nodes"),
    [selected],
  );

  return (
    <Drawer
      open={selected !== null}
      title={selected?.title ?? "Finding"}
      description={
        selected
          ? `${selected.finding_key} · ${selected.asset_key} · Updated ${formatExposureTimestamp(selected.updated_at)}`
          : ""
      }
      onClose={() => {
        setTab("overview");
        onClose();
      }}
      widthClassName="w-[720px]"
      headerLabel="Exposure Finding"
    >
      {selected ? (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Severity", value: selected.severity, variant: exposureSeverityVariant(selected.severity) },
              { label: "Status", value: selected.status },
              { label: "Score delta", value: selected.score_delta > 0 ? `+${selected.score_delta}` : String(selected.score_delta) },
              { label: "Confidence", value: formatExposureConfidence(selected.confidence) },
              { label: "Type", value: selected.finding_type },
              { label: "Evidence", value: `${selected.evidence_refs.length} refs` },
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

          {tab === "overview" ? (
            <>
              <InvestigationSection title="Finding detail" subtitle={selected.summary || "Authoritative exposure finding summary"}>
                <InvestigationSummaryGrid>
                  <InvestigationFactCard label="Finding key" value={selected.finding_key} mono copyValue={selected.finding_key} />
                  <InvestigationFactCard label="Asset key" value={selected.asset_key} mono copyValue={selected.asset_key} />
                  <InvestigationFactCard label="Agent" value={selected.agent_id || "-"} mono copyValue={selected.agent_id || undefined} />
                  <InvestigationFactCard label="First seen" value={formatExposureTimestamp(selected.first_seen_at)} mono />
                  <InvestigationFactCard label="Last seen" value={formatExposureTimestamp(selected.last_seen_at)} mono />
                  <InvestigationFactCard label="Updated" value={formatExposureTimestamp(selected.updated_at)} mono />
                  <InvestigationFactCard label="Related nodes" value={relatedNodeSummary} mono />
                </InvestigationSummaryGrid>
              </InvestigationSection>

              {selected.reason_codes.length > 0 ? (
                <InvestigationChipList
                  title="Reason codes"
                  chips={selected.reason_codes.map((code) => ({ label: code, variant: "neutral" as const }))}
                />
              ) : null}
            </>
          ) : null}

          {tab === "evidence" ? (
            <InvestigationSection title="Evidence references" subtitle="Bounded metadata only. Raw HTML is never rendered here.">
              <ExposureEvidenceList refs={selected.evidence_refs} />
            </InvestigationSection>
          ) : null}

          {tab === "recommendations" ? (
            <InvestigationSection title="Recommended actions" subtitle="Advisory only. No destructive response action runs automatically from this panel.">
              <ExposureRecommendationsPanel recommendations={selected.recommendations} />
            </InvestigationSection>
          ) : null}
        </InvestigationShell>
      ) : null}
    </Drawer>
  );
}
