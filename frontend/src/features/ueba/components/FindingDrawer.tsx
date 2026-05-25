import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Badge } from "@/shared/components/Badge";
import Drawer from "@/shared/components/Drawer";
import { SelectInput } from "@/shared/components/SelectInput";
import { TextArea } from "@/shared/components/TextArea";
import {
  InvestigationActionBar,
  InvestigationActionButton,
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

import { getUebaFinding, triageUebaFinding } from "../api";
import type { UebaFinding, UebaFindingDetail, UebaFindingStatus, UebaVerdict } from "../types";
import {
  baselineStatusVariant,
  detectorDescription,
  detectorLabel,
  findingStatusVariant,
  formatConfidence,
  formatExplanationEntries,
  formatMetricValue,
  formatTimestamp,
  metricLabel,
  reasonCodeLabel,
  relativeTime,
  severityVariant,
  verdictLabel,
  verdictVariant,
} from "./ueba-utils";

type Tab = "overview" | "evidence" | "raw";

const FP_TTL_OPTIONS: Array<{ label: string; value: string }> = [
  { label: "24 hours", value: "86400" },
  { label: "1 hour", value: "3600" },
  { label: "6 hours", value: "21600" },
  { label: "7 days", value: "604800" },
  { label: "Permanent", value: "permanent" },
];

function BaselineMaturityBar({ sampleCount, status }: { sampleCount: number; status: string }) {
  const pct =
    status === "mature"
      ? 100
      : Math.min(100, Math.round((sampleCount / Math.max(sampleCount * 1.5, 20)) * 100));

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-[11px] font-mono">
        <span className="text-muted-foreground">Maturity</span>
        <span className="text-foreground">
          {sampleCount} samples — {status === "mature" ? "mature" : "warming up"}
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

function HourHistogram({
  hourCounts,
  observedHour,
  expectedHour,
}: {
  hourCounts: number[];
  observedHour: number;
  expectedHour: number;
}) {
  const max = Math.max(...hourCounts, 1);
  return (
    <div>
      <div className="flex items-end gap-px h-8">
        {hourCounts.map((count, h) => (
          <div
            key={h}
            title={`${String(h).padStart(2, "0")}:00 — ${count}`}
            className={cx(
              "flex-1 rounded-sm min-h-[2px]",
              h === observedHour
                ? "bg-severity-high"
                : h === expectedHour
                  ? "bg-severity-low"
                  : "bg-muted/50",
            )}
            style={{ height: `${Math.max(4, (count / max) * 100)}%` }}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[9px] text-muted-foreground">
        <span>00:00</span>
        <span>
          <span className="text-severity-high">▲</span> observed ·{" "}
          <span className="text-severity-low">●</span> expected
        </span>
        <span>23:00</span>
      </div>
    </div>
  );
}

function DeviationBar({
  obs,
  exp,
  z,
  metricName,
}: {
  obs: number;
  exp: number;
  z: number;
  metricName: string;
}) {
  const spread = Math.abs(obs - exp) || exp * 0.1 || 1;
  const lo = Math.max(0, exp - spread * 0.5);
  const hi = exp + spread * 2;
  const range = hi - lo || 1;
  const obsPct = Math.min(100, Math.max(0, ((obs - lo) / range) * 100));
  const expPct = Math.min(100, Math.max(0, ((exp - lo) / range) * 100));

  return (
    <div className="space-y-1">
      <div className="relative h-2 w-full overflow-hidden rounded-full bg-muted/40">
        <div
          className="absolute inset-y-0 left-0 rounded-l-full bg-muted/50"
          style={{ width: `${expPct}%` }}
        />
        <div
          className={cx(
            "absolute top-0 h-full w-1.5 -translate-x-1/2 rounded-full",
            z >= 4
              ? "bg-severity-high"
              : z >= 2.5
                ? "bg-severity-medium"
                : "bg-severity-low",
          )}
          style={{ left: `${obsPct}%` }}
        />
      </div>
      <div className="flex justify-between font-mono text-[9px] text-muted-foreground">
        <span>{formatMetricValue(lo, metricName)}</span>
        <span className="opacity-60">baseline</span>
        <span>{formatMetricValue(hi, metricName)}</span>
      </div>
    </div>
  );
}

function DeviationBlock({ finding }: { finding: UebaFinding }) {
  const { observed_value: obs, expected_value: exp, deviation_score: z, metric_name } = finding;

  const hourCounts = (finding.explanation as Record<string, unknown>)?.hour_counts as
    | number[]
    | undefined;
  const isHourMetric =
    metric_name === "login_hour" || metric_name === "sudo_execution_hour";

  return (
    <div className="space-y-3 rounded-lg border border-border/60 bg-background/30 px-3 py-3">
      <div className="grid grid-cols-3 gap-3">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Observed
          </div>
          <div className="mt-1 font-mono text-sm font-semibold text-foreground">
            {obs != null ? formatMetricValue(obs, metric_name) : "—"}
          </div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Expected
          </div>
          <div className="mt-1 font-mono text-sm text-muted-foreground">
            {exp != null ? formatMetricValue(exp, metric_name) : "—"}
          </div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Deviation (z)
          </div>
          <div
            className={cx(
              "mt-1 font-mono text-sm font-semibold",
              z != null && z >= 4
                ? "text-severity-high"
                : z != null && z >= 2.5
                  ? "text-severity-medium"
                  : "text-foreground",
            )}
          >
            {z != null ? z.toFixed(2) : "—"}
          </div>
        </div>
      </div>

      {obs != null && exp != null && z != null && !isHourMetric && (
        <DeviationBar obs={obs} exp={exp} z={z} metricName={metric_name} />
      )}

      {isHourMetric && hourCounts && Array.isArray(hourCounts) && hourCounts.length === 24 && (
        <HourHistogram
          hourCounts={hourCounts}
          observedHour={obs != null ? Math.round(obs) % 24 : -1}
          expectedHour={exp != null ? Math.round(exp) % 24 : -1}
        />
      )}
    </div>
  );
}

function latestFeedback(detail: UebaFindingDetail | null) {
  const rows = detail?.feedback ?? [];
  return rows.length > 0 ? rows[0] : null;
}

function VerdictPanel({
  finding,
  detail,
  busy,
  onSubmit,
}: {
  finding: UebaFinding;
  detail: UebaFindingDetail | null;
  busy: boolean;
  onSubmit: (body: {
    verdict: UebaVerdict;
    notes?: string | null;
    suppression_ttl_seconds?: number | null;
    override?: boolean;
  }) => Promise<void>;
}) {
  const [pendingVerdict, setPendingVerdict] = useState<UebaVerdict | null>(null);
  const [notes, setNotes] = useState("");
  const [ttl, setTtl] = useState("86400");
  const [override, setOverride] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const feedback = latestFeedback(detail);
  const latestVerdict = feedback?.verdict ?? finding.latest_verdict;
  const latestBy = feedback?.annotated_by ?? finding.latest_verdict_by;
  const latestAt = feedback?.annotated_at ?? finding.latest_verdict_at;

  const submit = async () => {
    if (!pendingVerdict) return;
    setError(null);
    try {
      await onSubmit({
        verdict: pendingVerdict,
        notes: notes.trim() || null,
        suppression_ttl_seconds:
          pendingVerdict === "false_positive"
            ? ttl === "permanent"
              ? null
              : Number(ttl)
            : 0,
        override,
      });
      setPendingVerdict(null);
      setNotes("");
      setOverride(false);
    } catch (e: unknown) {
      setError((e as Error)?.message ?? "Verdict update failed");
    }
  };

  return (
    <InvestigationSection title="Analyst Verdict">
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          {latestVerdict ? (
            <>
              <Badge variant={verdictVariant(latestVerdict)}>{verdictLabel(latestVerdict)}</Badge>
              <span className="font-mono text-[11px] text-muted-foreground">
                {latestBy ?? "unknown"} · {latestAt ? formatTimestamp(latestAt) : "—"}
              </span>
            </>
          ) : (
            <Badge variant="neutral">Unreviewed</Badge>
          )}
        </div>

        <div className="grid gap-2 sm:grid-cols-3">
          {([
            ["true_positive", "Mark True Positive"],
            ["false_positive", "Mark False Positive"],
            ["benign_acknowledged", "Acknowledge as Benign"],
          ] as Array<[UebaVerdict, string]>).map(([verdict, label]) => (
            <button
              key={verdict}
              type="button"
              disabled={busy}
              onClick={() => {
                setPendingVerdict((current) => (current === verdict ? null : verdict));
                setError(null);
              }}
              className={cx(
                "rounded-md border px-3 py-2 text-left text-[12px] transition-colors",
                pendingVerdict === verdict
                  ? "border-severity-medium/60 bg-severity-medium/10 text-foreground"
                  : "border-border/60 bg-background/30 text-muted-foreground hover:text-foreground",
              )}
            >
              {label}
            </button>
          ))}
        </div>

        {pendingVerdict && (
          <div className="space-y-3 rounded-md border border-border/60 bg-background/30 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Badge variant={verdictVariant(pendingVerdict)}>{verdictLabel(pendingVerdict)}</Badge>
              {pendingVerdict === "false_positive" && (
                <SelectInput
                  value={ttl}
                  onChange={(event) => setTtl(event.target.value)}
                  className="h-8 min-w-[150px] text-xs font-mono"
                  aria-label="Suppression TTL"
                >
                  {FP_TTL_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </SelectInput>
              )}
            </div>
            <TextArea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              placeholder="Notes"
              maxLength={2000}
              className="min-h-[72px] text-xs"
            />
            {latestVerdict && latestVerdict !== pendingVerdict && (
              <label className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
                <input
                  type="checkbox"
                  checked={override}
                  onChange={(event) => setOverride(event.target.checked)}
                  className="h-3.5 w-3.5"
                />
                Record override
              </label>
            )}
            {error && <div className="font-mono text-[11px] text-severity-high">{error}</div>}
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setPendingVerdict(null)}
                disabled={busy}
                className="ui-btn-secondary h-8 px-3 text-xs"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={submit}
                disabled={busy}
                className="ui-btn-primary h-8 px-3 text-xs"
              >
                {busy ? "Submitting..." : "Confirm"}
              </button>
            </div>
          </div>
        )}
      </div>
    </InvestigationSection>
  );
}

export default function FindingDrawer({
  open,
  finding,
  onClose,
  onTriaged,
}: {
  open: boolean;
  finding: UebaFinding | null;
  onClose: () => void;
  onTriaged?: (updated: UebaFindingDetail) => void;
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

  const navigate = useNavigate();
  const [triageBusy, setTriageBusy] = useState(false);

  const f = detail ?? finding;
  const title = f ? `${detectorLabel(f.detector_id)} — ${f.entity_value}` : "Finding Detail";

  const doTriage = async (status: UebaFindingStatus) => {
    if (!f || triageBusy) return;
    setTriageBusy(true);
    try {
      const updated = await triageUebaFinding(f.id, { status });
      setDetail(updated);
      onTriaged?.(updated);
    } catch {
      // no-op
    } finally {
      setTriageBusy(false);
    }
  };

  const submitVerdict = async (body: {
    verdict: UebaVerdict;
    notes?: string | null;
    suppression_ttl_seconds?: number | null;
    override?: boolean;
  }) => {
    if (!f || triageBusy) return;
    setTriageBusy(true);
    try {
      const updated = await triageUebaFinding(f.id, body);
      setDetail(updated);
      onTriaged?.(updated);
    } finally {
      setTriageBusy(false);
    }
  };

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

          <InvestigationActionBar>
            {f.status === "open" && (
              <InvestigationActionButton onClick={() => doTriage("closed")} disabled={triageBusy}>
                {triageBusy ? "Closing..." : "Close finding"}
              </InvestigationActionButton>
            )}
            {f.status === "open" && (
              <InvestigationActionButton onClick={() => doTriage("suppressed")} disabled={triageBusy}>
                {triageBusy ? "Suppressing..." : "Suppress"}
              </InvestigationActionButton>
            )}
            {f.status !== "open" && (
              <InvestigationActionButton onClick={() => doTriage("open")} disabled={triageBusy}>
                Reopen
              </InvestigationActionButton>
            )}
            {f.alert_id != null && (
              <InvestigationActionButton
                tone="primary"
                onClick={() => {
                  onClose();
                  navigate(`/alerts/queue?search=${encodeURIComponent(String(f.alert_id))}`);
                }}
              >
                View alert ↗
              </InvestigationActionButton>
            )}
            {f.agent_id && (
              <InvestigationActionButton
                onClick={() => {
                  onClose();
                  navigate(`/events/stream?agent_id=${encodeURIComponent(f.agent_id!)}`);
                }}
              >
                Events for agent ↗
              </InvestigationActionButton>
            )}
          </InvestigationActionBar>

          {tab === "overview" && (
            <div className="space-y-4">
              <InvestigationSection title="Anomaly Analysis">
                <div className="space-y-3">
                  <DeviationBlock finding={f} />

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

              <VerdictPanel finding={f} detail={detail} busy={triageBusy} onSubmit={submitVerdict} />

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

              <InvestigationSection title="Detector">
                <div className="space-y-2 font-mono text-[12px]">
                  <div className="text-muted-foreground">{detectorDescription(f.detector_id)}</div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground text-[11px]">ID</span>
                    <span className="text-foreground text-[11px]">{f.detector_id}</span>
                  </div>
                  {f.cooldown_until && new Date(f.cooldown_until) > new Date() && (
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground text-[11px]">Cooldown until</span>
                      <span className="text-foreground text-[11px]">{formatTimestamp(f.cooldown_until)}</span>
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
