import { useEffect, useState } from "react";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import {
  InvestigationChipList,
  InvestigationFieldGroup,
  InvestigationListItem,
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  InvestigationStateBlock,
  InvestigationTabs,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";
import { cx } from "@/shared/lib/cx";

import { getUebaFinding } from "../api";
import type { UebaFinding, UebaFindingDetail } from "../types";
import {
  baselineStatusVariant,
  detectorLabel,
  findingStatusVariant,
  formatConfidence,
  formatExplanationEntries,
  formatTimestamp,
  metricLabel,
  reasonCodeLabel,
  relativeTime,
  severityVariant,
} from "./ueba-utils";

type Tab = "overview" | "evidence" | "raw";

function BaselineMaturityBar({ sampleCount, status }: { sampleCount: number; status: string }) {
  const MIN_SAMPLES_APPROX = 20;
  const pct = Math.min(100, Math.round((sampleCount / MIN_SAMPLES_APPROX) * 100));

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-[11px] font-mono">
        <span className="text-muted-foreground">Maturity</span>
        <span className="text-foreground">
          {sampleCount} samples{status === "mature" ? " — mature" : " — warming up"}
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted/50">
        <div
          className={cx(
            "h-full rounded-full transition-all",
            status === "mature" ? "bg-severity-low" : "bg-severity-medium",
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

export default function FindingDrawer({
  open,
  finding,
  onClose,
}: {
  open: boolean;
  finding: UebaFinding | null;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>("overview");
  const [detail, setDetail] = useState<UebaFindingDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !finding) {
      setDetail(null);
      setDetailError(null);
      return;
    }
    setTab("overview");
    setDetailLoading(true);
    setDetailError(null);
    const ctrl = new AbortController();
    getUebaFinding(finding.id, { signal: ctrl.signal })
      .then((d) => {
        if (!ctrl.signal.aborted) setDetail(d);
      })
      .catch((e: unknown) => {
        if (!ctrl.signal.aborted) setDetailError((e as Error)?.message ?? "Failed to load detail");
      })
      .finally(() => {
        if (!ctrl.signal.aborted) setDetailLoading(false);
      });
    return () => ctrl.abort();
  }, [open, finding?.id]);

  const f = detail ?? finding;
  const title = f ? `${detectorLabel(f.detector_id)} — ${f.entity_value}` : "Finding Detail";

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={title}
      headerLabel="Anomaly"
      description={f?.summary ?? undefined}
      widthClassName="w-[760px]"
    >
      {!f ? null : (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              { label: "Severity", value: f.severity, variant: severityVariant(f.severity) },
              { label: "Risk Score", value: String(f.risk_score) },
              { label: "Confidence", value: formatConfidence(f.confidence) },
              { label: "Status", value: f.status, variant: findingStatusVariant(f.status) },
              { label: "Entity", value: `${f.entity_type}: ${f.entity_value}` },
              { label: "Detector", value: detectorLabel(f.detector_id) },
              { label: "Metric", value: metricLabel(f.metric_name) },
              ...(f.mitre_tactic ? [{ label: "MITRE Tactic", value: f.mitre_tactic.replace(/_/g, " ") }] : []),
              ...(f.mitre_technique_id
                ? [{ label: "Technique", value: f.mitre_technique ? `${f.mitre_technique_id} — ${f.mitre_technique}` : f.mitre_technique_id }]
                : []),
            ]}
          />

          <InvestigationTabs
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "evidence", label: `Evidence${detail?.evidence?.length ? ` (${detail.evidence.length})` : ""}` },
              { key: "raw", label: "Raw" },
            ]}
          />

          {tab === "overview" && (
            <div className="space-y-4">
              <InvestigationSection title="Anomaly Analysis">
                <div className="space-y-3">
                  <div className="rounded-lg border border-border/60 bg-background/30 px-3 py-3">
                    <div className="grid grid-cols-3 gap-3">
                      <div>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Observed</div>
                        <div className="mt-1 font-mono text-sm font-semibold text-foreground">
                          {f.observed_value != null ? String(f.observed_value) : "—"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Expected</div>
                        <div className="mt-1 font-mono text-sm text-muted-foreground">
                          {f.expected_value != null ? String(f.expected_value) : "—"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Deviation (Z)</div>
                        <div className="mt-1 font-mono text-sm font-semibold text-severity-high">
                          {f.deviation_score != null ? f.deviation_score.toFixed(2) : "—"}
                        </div>
                      </div>
                    </div>
                  </div>

                  {f.reason_codes.length > 0 && (
                    <InvestigationChipList
                      title="Why it fired"
                      chips={f.reason_codes.map((code) => ({
                        label: reasonCodeLabel(code),
                        variant: "medium" as const,
                      }))}
                    />
                  )}

                  {Object.keys(f.explanation).length > 0 && (
                    <InvestigationFieldGroup
                      title="Statistical Detail"
                      entries={formatExplanationEntries(f.explanation, f.metric_name)}
                    />
                  )}
                </div>
              </InvestigationSection>

              <InvestigationSection title="Occurrence">
                <div className="grid grid-cols-2 gap-3 font-mono text-[12px]">
                  <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">First seen</div>
                    <div className="mt-1 text-foreground">{formatTimestamp(f.first_seen_at)}</div>
                  </div>
                  <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Last seen</div>
                    <div className="mt-1 text-foreground">{formatTimestamp(f.last_seen_at)}</div>
                  </div>
                  <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Occurrences</div>
                    <div className="mt-1 font-semibold text-foreground">{f.occurrence_count}</div>
                  </div>
                  {f.alert_id != null && (
                    <div className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
                      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Linked Alert</div>
                      <div className="mt-1 text-foreground">#{f.alert_id}</div>
                    </div>
                  )}
                </div>
              </InvestigationSection>

              {detail?.baseline && (
                <InvestigationSection title="Baseline">
                  <div className="space-y-3">
                    <BaselineMaturityBar
                      sampleCount={detail.baseline.sample_count}
                      status={detail.baseline.status}
                    />
                    <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                      <div className="flex items-center justify-between rounded-md border border-border/60 bg-background/30 px-3 py-2">
                        <span className="text-muted-foreground">Status</span>
                        <Badge variant={baselineStatusVariant(detail.baseline.status)}>
                          {detail.baseline.status}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between rounded-md border border-border/60 bg-background/30 px-3 py-2">
                        <span className="text-muted-foreground">Samples</span>
                        <span className="text-foreground">{detail.baseline.sample_count}</span>
                      </div>
                      {detail.baseline.expected_value != null && (
                        <div className="flex items-center justify-between rounded-md border border-border/60 bg-background/30 px-3 py-2">
                          <span className="text-muted-foreground">Expected</span>
                          <span className="text-foreground">{detail.baseline.expected_value.toFixed(2)}</span>
                        </div>
                      )}
                      {detail.baseline.dispersion != null && (
                        <div className="flex items-center justify-between rounded-md border border-border/60 bg-background/30 px-3 py-2">
                          <span className="text-muted-foreground">Dispersion</span>
                          <span className="text-foreground">{detail.baseline.dispersion.toFixed(3)}</span>
                        </div>
                      )}
                      <div className="flex items-center justify-between rounded-md border border-border/60 bg-background/30 px-3 py-2">
                        <span className="text-muted-foreground">Warmup started</span>
                        <span className="text-foreground">{relativeTime(detail.baseline.warmup_started_at)}</span>
                      </div>
                      {detail.baseline.matured_at && (
                        <div className="flex items-center justify-between rounded-md border border-border/60 bg-background/30 px-3 py-2">
                          <span className="text-muted-foreground">Matured</span>
                          <span className="text-foreground">{relativeTime(detail.baseline.matured_at)}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </InvestigationSection>
              )}

              {detailLoading && !detail && (
                <InvestigationStateBlock loading loadingLabel="Loading detail..." />
              )}
            </div>
          )}

          {tab === "evidence" && (
            <InvestigationSection title="Evidence">
              <InvestigationStateBlock
                loading={detailLoading && !detail}
                loadingLabel="Loading evidence..."
                error={detailError}
                empty={!detailLoading && !detailError && (detail?.evidence ?? []).length === 0}
                emptyTitle="No evidence"
                emptyHint="No evidence records were attached to this finding."
              />
              {(detail?.evidence ?? []).map((ev) => (
                <InvestigationListItem
                  key={ev.id}
                  title={ev.summary ?? `${ev.evidence_type} — ${ev.matched_field ?? "event"}`}
                  description={
                    ev.entity_value
                      ? `${ev.entity_type ?? "entity"}: ${ev.entity_value}`
                      : undefined
                  }
                  badges={[
                    { label: ev.evidence_role, variant: "neutral" as const },
                    ...(ev.matched_field && ev.matched_value
                      ? [{ label: `${ev.matched_field}: ${ev.matched_value}`, variant: "neutral" as const }]
                      : []),
                  ]}
                  meta={[
                    { label: "observed", value: formatInvestigationTimestamp(ev.observed_at) },
                    ...(ev.event_id != null ? [{ label: "event #", value: String(ev.event_id) }] : []),
                  ]}
                >
                  {Object.keys(ev.raw_context).length > 0 && (
                    <div className="mt-2 space-y-1">
                      {Object.entries(ev.raw_context)
                        .filter(([, v]) => v != null)
                        .map(([k, v]) => (
                          <div key={k} className="flex items-center gap-2 font-mono text-[10px]">
                            <span className="text-muted-foreground/70">{k}</span>
                            <span className="text-muted-foreground">{String(v)}</span>
                          </div>
                        ))}
                    </div>
                  )}
                </InvestigationListItem>
              ))}
            </InvestigationSection>
          )}

          {tab === "raw" && (
            <InvestigationRawJsonPanel value={detail ?? finding} title="Raw Finding" />
          )}
        </InvestigationShell>
      )}
    </Drawer>
  );
}
