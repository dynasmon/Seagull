import { useCallback, useState } from "react";

import { Button } from "@/shared/components/Button";
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
import { ExposureAssetDetail, ExposureAssetPosture, ExposureSeverity } from "../types";
import { ExposureRecommendationsPanel } from "./ExposureRecommendationsPanel";
import { ExposureScoreBreakdown } from "./ExposureScoreBreakdown";

function sevVariant(s: ExposureSeverity) {
  if (s === "informational") return "info" as const;
  if (s === "unknown") return "neutral" as const;
  return s as "critical" | "high" | "medium" | "low";
}

type Tab = "overview" | "findings" | "evidence" | "recommendations";

type Props = {
  asset: ExposureAssetPosture | null;
  detail: ExposureAssetDetail | null;
  detailLoading?: boolean;
  onClose: () => void;
  onOpenInvestigation?: (assetKey: string) => void;
  onCreateTriageAction?: (assetKey: string) => void;
  onViewGraph?: (assetKey: string) => void;
  isAdmin?: boolean;
};

export function ExposureAssetDrawer({
  asset,
  detail,
  detailLoading,
  onClose,
  onOpenInvestigation,
  onCreateTriageAction,
  onViewGraph,
  isAdmin,
}: Props) {
  const [tab, setTab] = useState<Tab>("overview");

  const handleClose = useCallback(() => {
    setTab("overview");
    onClose();
  }, [onClose]);

  const a = asset;

  return (
    <Drawer
      open={a !== null}
      title={a?.display_name ?? "Asset"}
      description={
        a
          ? `${a.asset_key} · ${a.asset_type} · Updated ${new Date(a.updated_at).toLocaleString()}`
          : ""
      }
      onClose={handleClose}
      widthClassName="w-[720px]"
      headerLabel="Exposure Asset"
    >
      {a && (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Severity", value: a.severity, variant: sevVariant(a.severity) },
              { label: "Risk score", value: String(a.risk_score) },
              { label: "Confidence", value: `${a.confidence}%` },
              { label: "Status", value: a.status },
              { label: "Criticality", value: a.criticality },
              { label: "Type", value: a.asset_type },
            ]}
          />

          <div className="flex flex-wrap gap-2">
            <Button variant="ghost" size="sm" onClick={() => onViewGraph?.(a.asset_key)}>
              View graph
            </Button>
            {isAdmin && (
              <>
                <Button variant="secondary" size="sm" onClick={() => onOpenInvestigation?.(a.asset_key)}>
                  Open investigation
                </Button>
                <Button variant="subtle" size="sm" onClick={() => onCreateTriageAction?.(a.asset_key)}>
                  Triage action
                </Button>
              </>
            )}
          </div>

          <InvestigationTabs
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "findings", label: "Findings" },
              { key: "evidence", label: "Evidence" },
              { key: "recommendations", label: "Actions" },
            ]}
          />

          {detailLoading && (
            <div className="py-4 text-center font-mono text-[11px] text-muted-foreground">Loading details…</div>
          )}

          {!detailLoading && tab === "overview" && (
            <>
              <InvestigationSection title="Asset details">
                <InvestigationSummaryGrid>
                  <InvestigationFactCard label="Asset key" value={a.asset_key} mono copyValue={a.asset_key} />
                  <InvestigationFactCard label="Type" value={a.asset_type} mono />
                  {a.hostname && <InvestigationFactCard label="Hostname" value={a.hostname} mono copyValue={a.hostname} />}
                  {a.environment && <InvestigationFactCard label="Environment" value={a.environment} mono />}
                  <InvestigationFactCard label="Criticality" value={a.criticality} mono />
                  {a.agent_id && <InvestigationFactCard label="Agent" value={a.agent_id} mono copyValue={a.agent_id} />}
                  <InvestigationFactCard label="First seen" value={new Date(a.first_seen_at).toLocaleString()} mono />
                  <InvestigationFactCard label="Last seen" value={new Date(a.last_seen_at).toLocaleString()} mono />
                </InvestigationSummaryGrid>
              </InvestigationSection>

              {a.reason_codes.length > 0 && (
                <InvestigationChipList
                  title="Reason codes"
                  chips={a.reason_codes.map((c) => ({ label: c, variant: "neutral" as const }))}
                />
              )}

              {detail && (
                <InvestigationSection title="Score breakdown">
                  <ExposureScoreBreakdown
                    breakdown={detail.score_breakdown}
                    explanation={detail.score_explanation}
                  />
                </InvestigationSection>
              )}

              {detail && detail.linked_investigations.length > 0 && (
                <InvestigationSection title={`Investigations (${detail.linked_investigations.length})`}>
                  <div className="space-y-2">
                    {detail.linked_investigations.map((inv) => (
                      <div key={inv.id} className="rounded-lg border border-border/60 bg-background/35 px-3 py-2">
                        <div className="text-sm font-medium">{inv.title}</div>
                        <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                          {inv.status} · {inv.severity} · {inv.priority}
                          {inv.assignee ? ` · ${inv.assignee}` : ""}
                        </div>
                      </div>
                    ))}
                  </div>
                </InvestigationSection>
              )}
            </>
          )}

          {!detailLoading && tab === "findings" && detail && (
            <InvestigationSection title={`Top findings (${detail.top_findings.length})`}>
              {detail.top_findings.length === 0 ? (
                <p className="text-sm text-muted-foreground">No top findings.</p>
              ) : (
                <div className="space-y-2">
                  {detail.top_findings.map((f) => (
                    <div
                      key={f.finding_key}
                      className="rounded-lg border border-border/60 bg-background/35 p-3"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[11px] text-danger">+{f.score_delta}</span>
                        <span className="font-mono text-[11px] text-muted-foreground">{f.finding_type}</span>
                        <span className="font-mono text-[11px] text-muted-foreground">{f.status}</span>
                      </div>
                      <div className="mt-1 text-sm font-medium">{f.title}</div>
                      {f.summary && (
                        <div className="mt-0.5 text-[12px] text-muted-foreground">{f.summary}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </InvestigationSection>
          )}

          {!detailLoading && tab === "evidence" && detail && (
            <InvestigationSection title="Evidence">
              {Object.entries(a.evidence_counts).length > 0 && (
                <div className="mb-3 flex flex-wrap gap-2">
                  {Object.entries(a.evidence_counts).map(([k, v]) => (
                    <span
                      key={k}
                      className="rounded border border-border/60 bg-background/35 px-2 py-0.5 font-mono text-[11px]"
                    >
                      {k}: {v}
                    </span>
                  ))}
                </div>
              )}
              {detail.linked_vulnerabilities.length > 0 && (
                <InvestigationChipList
                  title="Linked vulnerabilities"
                  chips={detail.linked_vulnerabilities.map((v) => ({
                    label: v.cve || v.title,
                    variant: sevVariant(v.severity),
                  }))}
                />
              )}
              {detail.linked_alerts.length > 0 && (
                <div className="mt-3">
                  <InvestigationChipList
                    title="Linked alerts"
                    chips={detail.linked_alerts.map((al) => ({
                      label: al.description,
                      variant: sevVariant(al.severity),
                    }))}
                  />
                </div>
              )}
            </InvestigationSection>
          )}

          {!detailLoading && tab === "recommendations" && detail && (
            <InvestigationSection title="Recommendations">
              <ExposureRecommendationsPanel recommendations={detail.top_recommendations} />
            </InvestigationSection>
          )}
        </InvestigationShell>
      )}
    </Drawer>
  );
}
