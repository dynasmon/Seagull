import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useAuth } from "@/features/auth/context";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import { IpAddressPill } from "@/shared/components/IpAddressPill";
import { InlineAlert } from "@/shared/components/InlineAlert";
import Loading from "@/shared/components/Loading";
import { Button } from "@/shared/components/Button";
import { Table } from "@/shared/components/Table";
import { Tabs } from "@/shared/components/Tabs";
import {
  InvestigationMetaStrip,
  InvestigationRawJsonPanel,
  InvestigationSection,
  InvestigationShell,
  formatInvestigationTimestamp,
} from "@/shared/components/investigation";

import type {
  CorrelationDurableIncident,
  CorrelationEvidence,
  CorrelationIncidentDetail,
  CorrelationLifecycleStatus,
} from "../types";
import CorrelationContextPanel from "./CorrelationContextPanel";
import CorrelationEvidenceList from "./CorrelationEvidenceList";
import CorrelationIncidentTimeline from "./CorrelationIncidentTimeline";
import CorrelationMitrePanel from "./CorrelationMitrePanel";
import {
  CorrelationConfidenceBadge,
  CorrelationRiskBadge,
  CorrelationStatusBadge,
} from "./CorrelationRiskBadge";
import CorrelationStatusActions from "./CorrelationStatusActions";
import { SeverityPill } from "@/shared/components/SeverityPill";
import { getFlowIpContext } from "@/shared/lib/ipClassification";
import {
  correlationEntityLabel,
  correlationSeverityVariant,
  isCorrelationAlertEvidence,
  isCorrelationNetEventEvidence,
} from "./correlationUtils";

type DrawerTab = "overview" | "timeline" | "evidence" | "raw";

function evidenceEndpoint(item: CorrelationEvidence, side: "src" | "dst") {
  const ip = side === "src" ? item.src_ip : item.dst_ip;
  const port = side === "src" ? null : item.dst_port;
  return (
    <span className="inline-flex max-w-full flex-wrap items-center gap-0.5">
      <IpAddressPill ip={ip} ipContext={getFlowIpContext(item.details?.ip_context as any, side)} compact />
      {typeof port === "number" ? <span className="text-muted-foreground">:{port}</span> : null}
    </span>
  );
}

function evidenceNetwork(rows: CorrelationEvidence[]) {
  return rows.map((item) => ({
    id: `${item.net_event_id ?? "na"}-${item.timestamp}-${item.evidence_type}`,
    when: formatInvestigationTimestamp(item.timestamp),
    type: String(item.details?.event_type || item.details?.kind || item.evidence_type || "event"),
    agent: String(item.details?.agent_id || item.details?.asset_agent_id || "-"),
    source: evidenceEndpoint(item, "src"),
    destination: evidenceEndpoint(item, "dst"),
    stage: item.stage || "-",
  }));
}

function evidenceAlerts(rows: CorrelationEvidence[]) {
  return rows.map((item) => ({
    id: `${item.alert_id ?? "na"}-${item.timestamp}`,
    when: formatInvestigationTimestamp(item.timestamp),
    severity: String(item.details?.severity || "-"),
    rule: item.rule_id || "-",
    source: evidenceEndpoint(item, "src"),
    destination: evidenceEndpoint(item, "dst"),
    description: String(item.details?.description || item.details?.label || "-"),
  }));
}

function incidentAgentId(
  incident: CorrelationDurableIncident | null,
  detail: CorrelationIncidentDetail | null,
): string {
  const resolved = detail || incident;
  if (!resolved) return "";
  if (String(resolved.entity_type || "") === "agent_id") return String(resolved.entity_value || "").trim();
  if (String(resolved.group_by || "") === "agent_id") return String(resolved.group_value || "").trim();
  for (const item of detail?.evidence ?? []) {
    const candidate = String(item.details?.agent_id || item.details?.asset_agent_id || "").trim();
    if (candidate) return candidate;
  }
  return "";
}

export default function CorrelationIncidentDrawer({
  open,
  incident,
  detail,
  loading,
  error,
  updatingStatus,
  statusError,
  onClose,
  onRefresh,
  onStatusChange,
  onOpenAlerts,
  onOpenInvestigations,
}: {
  open: boolean;
  incident: CorrelationDurableIncident | null;
  detail: CorrelationIncidentDetail | null;
  loading: boolean;
  error: string | null;
  updatingStatus: CorrelationLifecycleStatus | null;
  statusError: string | null;
  onClose: () => void;
  onRefresh: () => void;
  onStatusChange: (status: CorrelationLifecycleStatus, summary: string) => void;
  onOpenAlerts: () => void;
  onOpenInvestigations: () => void;
}) {
  const [tab, setTab] = useState<DrawerTab>("overview");
  const [summaryDraft, setSummaryDraft] = useState("");
  const navigate = useNavigate();
  const { user } = useAuth();
  const responseAgentId = useMemo(() => incidentAgentId(incident, detail), [incident, detail]);
  const canRespond = String(user?.role || "").toLowerCase() === "admin" && Boolean(responseAgentId);

  useEffect(() => {
    if (!open) {
      setTab("overview");
      return;
    }
    setSummaryDraft(detail?.summary || incident?.summary || "");
  }, [detail?.id, detail?.summary, detail?.updated_at, incident?.id, incident?.summary, open]);

  const resolved = detail || incident;
  const evidence = useMemo(() => detail?.evidence ?? [], [detail?.evidence]);
  const relatedAlerts = useMemo(() => evidence.filter(isCorrelationAlertEvidence), [evidence]);
  const relatedNetEvents = useMemo(() => evidence.filter(isCorrelationNetEventEvidence), [evidence]);

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={resolved?.correlation_rule_name || "Correlation incident"}
      description={
        resolved
          ? `${correlationEntityLabel(resolved.entity_type ?? null, resolved.entity_value ?? null, resolved.group_by, resolved.group_value).value} · last seen ${formatInvestigationTimestamp(resolved.last_seen_at || resolved.started_at)}`
          : ""
      }
      widthClassName="w-[980px]"
      headerLabel="Correlation incident"
      headerActions={
        <Button variant="subtle" size="sm" onClick={onRefresh}>
          Refresh
        </Button>
      }
    >
      {!incident ? (
        <EmptyState title="No incident selected" description="Choose a row from the incident queue first." />
      ) : loading && !detail ? (
        <Loading label="Loading incident detail..." />
      ) : error && !detail ? (
        <InlineAlert tone="danger">{error}</InlineAlert>
      ) : resolved ? (
        <InvestigationShell>
          {error && detail ? <InlineAlert tone="danger">{error}</InlineAlert> : null}

          <InvestigationMetaStrip
            items={[
              { label: "Status", value: <CorrelationStatusBadge status={resolved.status} /> },
              { label: "Severity", value: <SeverityPill variant={correlationSeverityVariant(resolved.severity)}>{resolved.severity}</SeverityPill> },
              { label: "Risk", value: <CorrelationRiskBadge score={resolved.risk_score} /> },
              { label: "Confidence", value: <CorrelationConfidenceBadge confidence={resolved.confidence} /> },
              { label: "Alerts", value: resolved.alert_count },
              { label: "Evidence", value: detail?.evidence.length ?? 0 },
            ]}
          />

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="subtle" size="lg" onClick={onOpenAlerts}>
              Open alerts queue
            </Button>
            <Button variant="subtle" size="lg" onClick={onOpenInvestigations}>
              Search investigations
            </Button>
            {canRespond ? (
              <Button
                variant="subtle"
                size="lg"
                onClick={() => navigate(`/response-center?agent_id=${encodeURIComponent(responseAgentId)}&mode=dispatch`)}
                title={`Dispatch a response action on ${responseAgentId}`}
              >
                Respond
              </Button>
            ) : null}
          </div>

          <Tabs
            value={tab}
            onChange={setTab}
            tabs={[
              { key: "overview", label: "Overview" },
              { key: "timeline", label: "Timeline" },
              { key: "evidence", label: "Evidence" },
              { key: "raw", label: "Raw" },
            ]}
          />

          {tab === "overview" ? (
            <>
              <CorrelationStatusActions
                currentStatus={resolved.status}
                summary={summaryDraft}
                busyStatus={updatingStatus}
                error={statusError}
                onSummaryChange={setSummaryDraft}
                onChangeStatus={(status) => onStatusChange(status, summaryDraft)}
              />

              <CorrelationContextPanel
                incident={{
                  correlation_rule_name: resolved.correlation_rule_name,
                  correlation_rule_id: resolved.correlation_rule_id,
                  entity_type: resolved.entity_type,
                  entity_value: resolved.entity_value,
                  group_by: resolved.group_by,
                  group_value: resolved.group_value,
                  dedup_key: resolved.dedup_key,
                  started_at: resolved.started_at,
                  last_seen_at: resolved.last_seen_at,
                  alert_count: resolved.alert_count,
                  unique_rules: resolved.unique_rules,
                  closed_at: resolved.closed_at,
                  summary: detail?.summary || incident.summary,
                  context: detail?.context || incident.context || {},
                }}
              />

              <CorrelationMitrePanel incident={detail} />

              <InvestigationSection
                title={`Related alerts (${relatedAlerts.length})`}
                subtitle="Persisted alert evidence attached to this incident."
              >
                {relatedAlerts.length > 0 ? (
                  <Table
                    columns={[
                      { key: "when", title: "Time" },
                      { key: "severity", title: "Severity" },
                      { key: "rule", title: "Rule" },
                      { key: "source", title: "Source" },
                      { key: "destination", title: "Destination" },
                      { key: "description", title: "Description", className: "min-w-[240px]" },
                    ]}
                    rows={evidenceAlerts(relatedAlerts)}
                    rowKey={(row) => row.id}
                    compact
                  />
                ) : (
                  <div className="rounded-md border border-border bg-surface-2/40 px-3 py-2 text-sm text-muted-foreground">
                    No related alerts were persisted for this incident.
                  </div>
                )}
              </InvestigationSection>

              <InvestigationSection
                title={`Related net events (${relatedNetEvents.length})`}
                subtitle="Network or event pivots attached to this incident when available."
              >
                {relatedNetEvents.length > 0 ? (
                  <Table
                    columns={[
                      { key: "when", title: "Time" },
                      { key: "type", title: "Type" },
                      { key: "agent", title: "Agent" },
                      { key: "source", title: "Source" },
                      { key: "destination", title: "Destination" },
                      { key: "stage", title: "Stage" },
                    ]}
                    rows={evidenceNetwork(relatedNetEvents)}
                    rowKey={(row) => row.id}
                    compact
                  />
                ) : (
                  <div className="rounded-md border border-border bg-surface-2/40 px-3 py-2 text-sm text-muted-foreground">
                    No related network events were persisted for this incident.
                  </div>
                )}
              </InvestigationSection>
            </>
          ) : null}

          {tab === "timeline" ? (
            <InvestigationSection title="Timeline" subtitle="Chronological persisted evidence across the incident lifecycle.">
              <CorrelationIncidentTimeline evidence={evidence} />
            </InvestigationSection>
          ) : null}

          {tab === "evidence" ? (
            <InvestigationSection title="Evidence list" subtitle="Full persisted evidence set with raw detail blocks.">
              <CorrelationEvidenceList evidence={evidence} />
            </InvestigationSection>
          ) : null}

          {tab === "raw" ? <InvestigationRawJsonPanel title="Incident JSON" value={detail || incident} /> : null}
        </InvestigationShell>
      ) : null}
    </Drawer>
  );
}
