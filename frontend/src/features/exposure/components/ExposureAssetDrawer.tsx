import { useCallback, useMemo, useState } from "react";

import { TimeSeriesChart, useSeverityChartColors } from "@/shared/components/charts";
import Loading from "@/shared/components/Loading";
import Drawer from "@/shared/components/Drawer";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { InlineAlert } from "@/shared/components/InlineAlert";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationChipList,
  InvestigationFactCard,
  InvestigationListItem,
  InvestigationMetaStrip,
  InvestigationSection,
  InvestigationShell,
  InvestigationSummaryGrid,
  InvestigationTabs,
} from "@/shared/components/investigation";
import { copyTextToClipboard } from "@/shared/components/investigation/utils";

import {
  ExposureAssetDetail,
  ExposureAssetPosture,
  ExposureInvestigationResult,
  ExposureSeverity,
  ExposureTriageResponseAction,
} from "../types";
import {
  exposureSeverityVariant,
  formatExposureConfidence,
  formatExposureScore,
  formatExposureTimestamp,
  truncateText,
} from "../utils";
import { ExposureRecommendationsPanel } from "./ExposureRecommendationsPanel";
import { ExposureScoreBreakdown } from "./ExposureScoreBreakdown";

type Tab = "overview" | "findings" | "linked" | "history" | "actions";

type Props = {
  asset: ExposureAssetPosture | null;
  detail: ExposureAssetDetail | null;
  detailLoading?: boolean;
  detailError?: string | null;
  onClose: () => void;
  onOpenInvestigation?: (assetKey: string) => Promise<ExposureInvestigationResult | void>;
  onCreateTriageAction?: (assetKey: string) => Promise<ExposureTriageResponseAction | void>;
  onRefreshAsset?: (assetKey: string) => Promise<void>;
  onViewGraph?: (assetKey: string) => void;
  isAdmin?: boolean;
};

function severityVariant(value: ExposureSeverity) {
  return exposureSeverityVariant(value);
}

function ScoreHistoryChart({ detail }: { detail: ExposureAssetDetail }) {
  const severityColors = useSeverityChartColors();
  const data = useMemo(
    () =>
      detail.recent_score_history.map((point) => ({
        t: formatExposureTimestamp(point.bucket_ts).slice(11),
        risk: point.risk_score,
        confidence: point.confidence,
      })),
    [detail.recent_score_history],
  );

  if (data.length < 2) {
    return <p className="text-sm text-muted-foreground">Insufficient score history for a trend view.</p>;
  }

  return (
    <TimeSeriesChart
      data={data}
      seriesKeys={["risk", "confidence"]}
      seriesNames={{ risk: "Risk score", confidence: "Confidence" }}
      height={240}
      curve="monotone"
      colorFor={(key) => (key === "risk" ? severityColors.critical : severityColors.low)}
    />
  );
}

export function ExposureAssetDrawer({
  asset,
  detail,
  detailLoading,
  detailError,
  onClose,
  onOpenInvestigation,
  onCreateTriageAction,
  onRefreshAsset,
  onViewGraph,
  isAdmin,
}: Props) {
  const [tab, setTab] = useState<Tab>("overview");
  const [actionBusy, setActionBusy] = useState<null | "investigation" | "triage" | "refresh" | "copy">(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const posture = detail?.posture ?? asset;

  const resetLocalState = useCallback(() => {
    setTab("overview");
    setActionBusy(null);
    setActionMessage(null);
    setActionError(null);
    onClose();
  }, [onClose]);

  const runAction = useCallback(
    async <T,>(kind: "investigation" | "triage" | "refresh" | "copy", task: () => Promise<T>, onSuccess: (value: T) => string) => {
      setActionBusy(kind);
      setActionError(null);
      setActionMessage(null);
      try {
        const result = await task();
        setActionMessage(onSuccess(result));
      } catch (error) {
        setActionError(error instanceof Error ? error.message : "Action failed");
      } finally {
        setActionBusy(null);
      }
    },
    [],
  );

  if (!posture) return null;

  return (
    <Drawer
      open={asset !== null}
      title={posture.display_name}
      description={`${posture.asset_key} · ${posture.asset_type} · Updated ${formatExposureTimestamp(detail?.updated_at || posture.updated_at)}`}
      onClose={resetLocalState}
      widthClassName="w-[960px]"
      headerLabel="Exposure Asset"
    >
      <InvestigationShell>
        <InvestigationMetaStrip
          items={[
            { label: "Severity", value: posture.severity, variant: severityVariant(posture.severity) },
            { label: "Risk score", value: formatExposureScore(posture.risk_score) },
            { label: "Confidence", value: formatExposureConfidence(posture.confidence) },
            { label: "Status", value: posture.status },
            { label: "Criticality", value: posture.criticality },
            { label: "Type", value: posture.asset_type },
          ]}
        />

        <InvestigationActionBar>
          {isAdmin ? (
            <InvestigationActionButton
              tone="primary"
              disabled={actionBusy !== null || !onOpenInvestigation}
              onClick={() =>
                onOpenInvestigation
                  ? runAction(
                      "investigation",
                      () => onOpenInvestigation(posture.asset_key),
                      (result) => {
                        const value = result as ExposureInvestigationResult | void;
                        if (!value) return "Investigation request submitted";
                        return value.created
                          ? `Investigation ${value.workspace_key} created`
                          : `Investigation ${value.workspace_key} opened`;
                      },
                    )
                  : undefined
              }
            >
              Open/Create Investigation
            </InvestigationActionButton>
          ) : null}

          {isAdmin ? (
            <InvestigationActionButton
              disabled={actionBusy !== null || !onCreateTriageAction || !posture.agent_id}
              onClick={() =>
                onCreateTriageAction
                  ? runAction(
                      "triage",
                      () => onCreateTriageAction(posture.asset_key),
                      (result) => {
                        const value = result as ExposureTriageResponseAction | void;
                        return value ? `Safe triage action #${value.action_id} queued` : "Safe triage action queued";
                      },
                    )
                  : undefined
              }
            >
              Trigger Safe Triage Action
            </InvestigationActionButton>
          ) : null}

          <InvestigationActionButton
            disabled={actionBusy !== null || !onRefreshAsset}
            onClick={() =>
              onRefreshAsset
                ? runAction("refresh", () => onRefreshAsset(posture.asset_key), () => "Asset detail refreshed")
                : undefined
            }
          >
            Refresh Asset
          </InvestigationActionButton>

          <InvestigationActionButton
            disabled={actionBusy !== null}
            onClick={() =>
              runAction(
                "copy",
                async () => {
                  const ok = await copyTextToClipboard(posture.asset_key);
                  if (!ok) throw new Error("Copy failed");
                  return ok;
                },
                () => "Asset key copied",
              )
            }
          >
            Copy Asset Key
          </InvestigationActionButton>

          {onViewGraph ? (
            <InvestigationActionButton
              disabled={actionBusy !== null}
              onClick={() => onViewGraph(posture.asset_key)}
            >
              View Graph
            </InvestigationActionButton>
          ) : null}
        </InvestigationActionBar>

        {actionError ? <InlineAlert tone="danger">{actionError}</InlineAlert> : null}
        {actionMessage ? <InlineAlert tone="success">{actionMessage}</InlineAlert> : null}
        {detailError && detail ? <InlineAlert tone="warning">{detailError}</InlineAlert> : null}
        {detailLoading && detail ? <div className="text-[11px] font-mono text-muted-foreground">Refreshing authoritative posture…</div> : null}

        <InvestigationTabs
          value={tab}
          onChange={setTab}
          tabs={[
            { key: "overview", label: "Overview" },
            { key: "findings", label: "Findings" },
            { key: "linked", label: "Linked" },
            { key: "history", label: "History" },
            { key: "actions", label: "Actions" },
          ]}
        />

        {!detail && detailLoading ? <Loading label="Loading exposure asset detail..." /> : null}

        {!detail && detailError ? (
          <InlineAlert tone="danger">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <span>{detailError}</span>
              {onRefreshAsset ? (
                <InvestigationActionButton onClick={() => void onRefreshAsset(posture.asset_key)}>
                  Retry Refresh
                </InvestigationActionButton>
              ) : null}
            </div>
          </InlineAlert>
        ) : null}

        {tab === "overview" ? (
          <>
            <InvestigationSection title="Asset identity">
              <InvestigationSummaryGrid>
                <InvestigationFactCard label="Asset key" value={posture.asset_key} mono copyValue={posture.asset_key} />
                <InvestigationFactCard label="Agent" value={posture.agent_id || "-"} mono copyValue={posture.agent_id || undefined} />
                <InvestigationFactCard label="Hostname" value={posture.hostname || "-"} mono copyValue={posture.hostname || undefined} />
                <InvestigationFactCard label="Environment" value={posture.environment || "-"} />
                <InvestigationFactCard label="First seen" value={formatExposureTimestamp(posture.first_seen_at)} mono />
                <InvestigationFactCard label="Last seen" value={formatExposureTimestamp(posture.last_seen_at)} mono />
              </InvestigationSummaryGrid>
            </InvestigationSection>

            {detail?.reason_codes?.length ? (
              <InvestigationChipList
                title="Reason codes"
                chips={detail.reason_codes.map((code) => ({ label: code, variant: "neutral" as const }))}
              />
            ) : posture.reason_codes.length ? (
              <InvestigationChipList
                title="Reason codes"
                chips={posture.reason_codes.map((code) => ({ label: code, variant: "neutral" as const }))}
              />
            ) : null}

            {detail ? (
              <InvestigationSection title="Score breakdown" subtitle={detail.score_explanation.confidence_note || "Authoritative backend score composition"}>
                <ExposureScoreBreakdown breakdown={detail.score_breakdown} explanation={detail.score_explanation} />
              </InvestigationSection>
            ) : null}

            {detail ? (
              <InvestigationSection title="Current linkage" subtitle="High-signal linked entities used in exposure prioritization.">
                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
                  <InvestigationFactCard label="Findings" value={detail.top_findings.length} />
                  <InvestigationFactCard label="Attack cases" value={detail.linked_attack_chain_cases.length} />
                  <InvestigationFactCard label="Vulnerabilities" value={detail.linked_vulnerabilities.length} />
                  <InvestigationFactCard label="Alerts" value={detail.linked_alerts.length} />
                  <InvestigationFactCard label="Investigations" value={detail.linked_investigations.length} />
                </div>
              </InvestigationSection>
            ) : null}
          </>
        ) : null}

        {tab === "findings" ? (
          <InvestigationSection
            title={`Top findings${detail ? ` (${detail.top_findings.length})` : ""}`}
            subtitle="Highest-score contributing findings for this asset."
          >
            {!detail ? (
              <p className="text-sm text-muted-foreground">Asset detail is required to load findings.</p>
            ) : detail.top_findings.length === 0 ? (
              <p className="text-sm text-muted-foreground">No backend findings are attached to this asset.</p>
            ) : (
              <div className="space-y-3">
                {detail.top_findings.map((finding) => (
                  <InvestigationListItem
                    key={finding.finding_key}
                    title={finding.title}
                    description={finding.summary}
                    badges={[
                      { label: finding.severity, variant: exposureSeverityVariant(finding.severity) },
                      { label: finding.finding_type, variant: "neutral" },
                      { label: finding.status, variant: "neutral" },
                    ]}
                    meta={[
                      { label: "score", value: finding.score_delta > 0 ? `+${finding.score_delta}` : String(finding.score_delta) },
                      { label: "confidence", value: formatExposureConfidence(finding.confidence) },
                      { label: "last seen", value: formatExposureTimestamp(finding.last_seen_at) },
                    ]}
                  />
                ))}
              </div>
            )}
          </InvestigationSection>
        ) : null}

        {tab === "linked" ? (
          <>
            <InvestigationSection
              title={`Attack-chain cases${detail ? ` (${detail.linked_attack_chain_cases.length})` : ""}`}
              subtitle="Linked backend cases and their most recent progression."
            >
              {!detail ? (
                <p className="text-sm text-muted-foreground">Asset detail is required to load linked cases.</p>
              ) : detail.linked_attack_chain_cases.length === 0 ? (
                <p className="text-sm text-muted-foreground">No linked attack-chain cases.</p>
              ) : (
                <div className="space-y-3">
                  {detail.linked_attack_chain_cases.map((item) => (
                    <InvestigationListItem
                      key={item.id}
                      title={`Case ${item.id} · ${item.max_stage.replaceAll("_", " ")}`}
                      description={item.suspect_ip ? `Suspect IP ${item.suspect_ip}` : "No suspect IP attached"}
                      badges={[
                        { label: item.status, variant: "neutral" },
                        { label: `score ${item.score}`, variant: "critical" },
                      ]}
                      meta={[
                        { label: "steps", value: item.step_count },
                        { label: "last seen", value: formatExposureTimestamp(item.last_seen_at) },
                      ]}
                    >
                      {item.recent_steps.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                          {item.recent_steps.map((step) => (
                            <span key={step.id} className="rounded-sm border border-border/60 bg-background/35 px-2 py-1 text-[11px] text-muted-foreground">
                              {truncateText(step.label, 64)}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </InvestigationListItem>
                  ))}
                </div>
              )}
            </InvestigationSection>

            <InvestigationSection title={`Linked vulnerabilities${detail ? ` (${detail.linked_vulnerabilities.length})` : ""}`}>
              {!detail ? (
                <p className="text-sm text-muted-foreground">Asset detail is required to load vulnerability context.</p>
              ) : detail.linked_vulnerabilities.length === 0 ? (
                <p className="text-sm text-muted-foreground">No linked vulnerabilities.</p>
              ) : (
                <div className="space-y-3">
                  {detail.linked_vulnerabilities.map((item) => (
                    <InvestigationListItem
                      key={item.id}
                      title={item.cve || item.title}
                      description={item.description || item.remediation}
                      badges={[
                        { label: item.severity, variant: exposureSeverityVariant(item.severity) },
                        { label: item.observation_state, variant: "neutral" },
                      ]}
                      meta={[
                        { label: "confidence", value: formatExposureConfidence(item.confidence) },
                        { label: "location", value: item.location || "-" },
                        { label: "last seen", value: formatExposureTimestamp(item.last_seen_at) },
                      ]}
                    />
                  ))}
                </div>
              )}
            </InvestigationSection>

            <InvestigationSection title={`Linked alerts${detail ? ` (${detail.linked_alerts.length})` : ""}`}>
              {!detail ? (
                <p className="text-sm text-muted-foreground">Asset detail is required to load alert context.</p>
              ) : detail.linked_alerts.length === 0 ? (
                <p className="text-sm text-muted-foreground">No linked alerts.</p>
              ) : (
                <div className="space-y-3">
                  {detail.linked_alerts.map((item) => (
                    <InvestigationListItem
                      key={item.id}
                      title={item.description}
                      description={item.mitre_tactic || item.mitre_technique || item.rule_id}
                      badges={[
                        { label: item.severity, variant: exposureSeverityVariant(item.severity) },
                        { label: item.rule_id, variant: "neutral" },
                      ]}
                      meta={[
                        { label: "confidence", value: formatExposureConfidence(item.confidence) },
                        { label: "src", value: <IpAddressPill ip={item.src_ip} compact /> },
                        { label: "created", value: formatExposureTimestamp(item.created_at) },
                      ]}
                    />
                  ))}
                </div>
              )}
            </InvestigationSection>

            <InvestigationSection title={`Linked investigations${detail ? ` (${detail.linked_investigations.length})` : ""}`}>
              {!detail ? (
                <p className="text-sm text-muted-foreground">Asset detail is required to load investigation context.</p>
              ) : detail.linked_investigations.length === 0 ? (
                <p className="text-sm text-muted-foreground">No linked investigations.</p>
              ) : (
                <div className="space-y-3">
                  {detail.linked_investigations.map((item) => (
                    <InvestigationListItem
                      key={item.id}
                      title={item.title}
                      description={item.workspace_key}
                      badges={[
                        { label: item.status, variant: "neutral" },
                        { label: item.priority, variant: "neutral" },
                      ]}
                      meta={[
                        { label: "severity", value: item.severity },
                        { label: "assignee", value: item.assignee || "-" },
                        { label: "updated", value: formatExposureTimestamp(item.updated_at) },
                      ]}
                    />
                  ))}
                </div>
              )}
            </InvestigationSection>

            <InvestigationSection title={`Linked response actions${detail ? ` (${detail.linked_response_actions.length})` : ""}`} subtitle="Listed actions are historical or queued records. Nothing executes automatically from this drawer.">
              {!detail ? (
                <p className="text-sm text-muted-foreground">Asset detail is required to load response context.</p>
              ) : detail.linked_response_actions.length === 0 ? (
                <p className="text-sm text-muted-foreground">No linked response actions.</p>
              ) : (
                <div className="space-y-3">
                  {detail.linked_response_actions.map((item) => (
                    <InvestigationListItem
                      key={item.id}
                      title={`${item.action_type} #${item.id}`}
                      description={item.last_error || item.latest_result_status || item.status}
                      badges={[
                        { label: item.status, variant: "neutral" },
                        { label: item.latest_result_status || "no result", variant: "neutral" },
                      ]}
                      meta={[
                        { label: "requested by", value: item.requested_by },
                        { label: "requested", value: formatExposureTimestamp(item.requested_at) },
                        { label: "expires", value: formatExposureTimestamp(item.expires_at) },
                      ]}
                    />
                  ))}
                </div>
              )}
            </InvestigationSection>
          </>
        ) : null}

        {tab === "history" ? (
          <InvestigationSection title="Recent score history" subtitle="Backend time-bucketed posture history for this asset.">
            {!detail ? (
              <p className="text-sm text-muted-foreground">Asset detail is required to load score history.</p>
            ) : (
              <div className="space-y-4">
                <ScoreHistoryChart detail={detail} />
                <div className="space-y-2">
                  {detail.recent_score_history.slice(-8).reverse().map((point) => (
                    <div key={point.bucket_ts} className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border/60 bg-background/30 px-3 py-2 text-[11px]">
                      <span className="font-mono text-muted-foreground">{formatExposureTimestamp(point.bucket_ts)}</span>
                      <div className="flex flex-wrap items-center gap-3 font-mono text-foreground">
                        <span>risk {formatExposureScore(point.risk_score)}</span>
                        <span>confidence {formatExposureConfidence(point.confidence)}</span>
                        <span>{point.severity}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </InvestigationSection>
        ) : null}

        {tab === "actions" ? (
          <InvestigationSection title="Top recommendations" subtitle="Backend-prioritized action guidance only. Analyst review remains required for any operational step.">
            {!detail ? (
              <p className="text-sm text-muted-foreground">Asset detail is required to load recommendations.</p>
            ) : (
              <ExposureRecommendationsPanel recommendations={detail.top_recommendations} />
            )}
          </InvestigationSection>
        ) : null}
      </InvestigationShell>
    </Drawer>
  );
}
