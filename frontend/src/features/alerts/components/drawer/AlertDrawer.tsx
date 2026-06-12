import { useAuth } from "@/features/auth/context";
import Drawer from "@/shared/components/Drawer";
import EmptyState from "@/shared/components/EmptyState";
import {
  InvestigationActionBar,
  InvestigationActionButton,
  InvestigationMetaStrip,
  InvestigationShell,
  InvestigationTabs,
} from "@/shared/components/investigation";

import { fmtTs } from "../../lib/alertFormatters";
import { sevVariant } from "../../lib/alertSeverity";
import type { AlertsPageModel } from "../../hooks/useAlertsPageModel";
import { AlertDrawerEvidenceTab } from "./AlertDrawerEvidenceTab";
import { AlertDrawerRawTab } from "./AlertDrawerRawTab";
import { AlertDrawerSummaryTab } from "./AlertDrawerSummaryTab";
import { AlertDrawerTriageTab } from "./AlertDrawerTriageTab";

export function AlertDrawer({ model }: { model: AlertsPageModel }) {
  const { drawer, evidence, actions, query } = model;
  const { selected } = drawer;
  const { user } = useAuth();
  const canRespond = String(user?.role || "").toLowerCase() === "admin" && Boolean(actions.responseAgentId);

  return (
    <Drawer
      open={drawer.drawerOpen}
      onClose={drawer.closeDrawer}
      title={selected ? `Alert #${selected.id}` : "Alert"}
      description={selected ? `${selected.rule_id} · ${fmtTs(selected.created_at)}` : undefined}
      widthClassName="w-[980px]"
      headerLabel="Alert"
    >
      {!selected ? (
        <EmptyState title="No selection" description="Select an alert using the View action in the queue." />
      ) : (
        <InvestigationShell>
          <InvestigationMetaStrip
            items={[
              {
                label: "Severity",
                value: String(selected.severity || "unknown"),
                variant: sevVariant(String(selected.severity || "unknown")),
              },
              { label: "Status", value: selected.status ?? "open" },
              { label: "Rule", value: selected.rule_id },
              { label: "Created", value: fmtTs(selected.created_at) },
              {
                label: "ATT&CK",
                value:
                  selected.mitre_technique_id || selected.mitre_tactic
                    ? `${selected.mitre_tactic || "tactic"}${selected.mitre_technique_id ? ` · ${selected.mitre_technique_id}` : ""}`
                    : "-",
              },
            ]}
          />

          <InvestigationActionBar>
            <InvestigationActionButton onClick={actions.openRuleEditor} title="Open rule editor">
              Edit rule
            </InvestigationActionButton>
            <InvestigationActionButton onClick={actions.openEventsPivot} title="Pivot into Events">
              Open in Events
            </InvestigationActionButton>
            {canRespond ? (
              <InvestigationActionButton
                onClick={actions.openResponsePivot}
                title={`Dispatch a response action on ${actions.responseAgentId}`}
              >
                Respond
              </InvestigationActionButton>
            ) : null}
            <InvestigationActionButton onClick={actions.copyDetailsJson} title="Copy JSON to clipboard">
              {drawer.copied ? "Copied" : "Copy JSON"}
            </InvestigationActionButton>
          </InvestigationActionBar>

          <InvestigationTabs
            value={drawer.drawerTab}
            onChange={drawer.setDrawerTab}
            tabs={[
              { key: "summary", label: "Summary" },
              { key: "evidence", label: "Evidence" },
              { key: "triage", label: "Triage" },
              { key: "raw", label: "Raw" },
            ]}
          />

          {drawer.drawerTab === "summary" ? <AlertDrawerSummaryTab selected={selected} /> : null}

          {drawer.drawerTab === "evidence" ? (
            <AlertDrawerEvidenceTab
              selected={selected}
              evidenceItems={evidence.evidenceItems}
              evidenceLoading={evidence.evidenceLoading}
            />
          ) : null}

          {drawer.drawerTab === "triage" ? (
            <AlertDrawerTriageTab
              selected={selected}
              triaging={actions.triaging}
              triageError={actions.triageError}
              triageNotes={drawer.triageNotes}
              setTriageNotes={drawer.setTriageNotes}
              triageAssignedTo={drawer.triageAssignedTo}
              setTriageAssignedTo={drawer.setTriageAssignedTo}
              triagePriority={drawer.triagePriority}
              setTriagePriority={drawer.setTriagePriority}
              triageRiskScore={drawer.triageRiskScore}
              setTriageRiskScore={drawer.setTriageRiskScore}
              triageCloseDisposition={drawer.triageCloseDisposition}
              setTriageCloseDisposition={drawer.setTriageCloseDisposition}
              onStatusAction={actions.triageStatusAction}
              onCloseAction={actions.triageCloseAction}
              onSaveFields={actions.handleTriageFieldsSave}
            />
          ) : null}

          {drawer.drawerTab === "raw" ? (
            <AlertDrawerRawTab selected={selected} initialWrap={query.view.wrap_json} />
          ) : null}
        </InvestigationShell>
      )}
    </Drawer>
  );
}
