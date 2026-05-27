import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { copyTextToClipboard } from "@/shared/components/investigation";

import { triageAlert } from "../api";
import { safeJson } from "../lib/alertFormatters";
import type { Alert, AlertDisposition, AlertStatus, AlertTriageIn } from "../types";

interface UseAlertInvestigationActionsParams {
  selected: Alert | null;
  triageNotes: string;
  triageAssignedTo: string;
  triagePriority: string;
  triageRiskScore: string;
  triageCloseDisposition: AlertDisposition | "";
  onAlertUpdated: (alert: Alert) => void;
  onCopied: () => void;
}

export function useAlertInvestigationActions({
  selected,
  triageNotes,
  triageAssignedTo,
  triagePriority,
  triageRiskScore,
  triageCloseDisposition,
  onAlertUpdated,
  onCopied,
}: UseAlertInvestigationActionsParams) {
  const nav = useNavigate();
  const [triaging, setTriaging] = useState(false);
  const [triageError, setTriageError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  async function handleTriage(patch: AlertTriageIn) {
    if (!selected) return;
    setTriaging(true);
    setTriageError(null);
    try {
      const updated = await triageAlert(selected.id, patch);
      onAlertUpdated(updated);
    } catch (e: any) {
      setTriageError(e?.message || "Triage failed");
    } finally {
      setTriaging(false);
    }
  }

  function handleTriageFieldsSave() {
    if (!selected) return;
    const body: AlertTriageIn = {};
    if (triageNotes !== (selected.triage_notes ?? "")) body.triage_notes = triageNotes || null;
    if (triageAssignedTo !== (selected.assigned_to ?? "")) body.assigned_to = triageAssignedTo || null;
    const p = parseInt(triagePriority, 10);
    if (triagePriority !== (selected.priority != null ? String(selected.priority) : "")) {
      body.priority = triagePriority ? (Number.isFinite(p) ? p : null) : null;
    }
    const rs = parseInt(triageRiskScore, 10);
    if (triageRiskScore !== (selected.risk_score != null ? String(selected.risk_score) : "")) {
      body.risk_score = triageRiskScore ? (Number.isFinite(rs) ? rs : null) : null;
    }
    if (Object.keys(body).length === 0) return;
    void handleTriage(body);
  }

  async function copyDetailsJson() {
    if (!selected) return;
    const json = safeJson({
      id: selected.id,
      severity: selected.severity,
      rule_id: selected.rule_id,
      src_ip: selected.src_ip,
      dst_ip: selected.dst_ip,
      dst_port: selected.dst_port,
      confidence: selected.confidence,
      mitre_tactic: selected.mitre_tactic,
      mitre_technique_id: selected.mitre_technique_id,
      mitre_technique: selected.mitre_technique,
      created_at: selected.created_at,
      description: selected.description,
      details: selected.details,
    });
    const ok = await copyTextToClipboard(json);
    if (ok) onCopied();
  }

  function openRuleEditor() {
    if (!selected?.rule_id) return;
    nav(`/alerts/rules?rule_id=${encodeURIComponent(selected.rule_id)}`);
  }

  function openEventsPivot() {
    if (!selected) return;
    const sp = new URLSearchParams();
    const primaryQuery =
      (selected.src_ip || "").trim() ||
      (selected.dst_ip || "").trim() ||
      (selected.mitre_technique_id || "").trim() ||
      (selected.rule_id || "").trim();
    if (primaryQuery) sp.set("search", primaryQuery);
    nav(`/events${sp.toString() ? `?${sp.toString()}` : ""}`);
  }

  function openSelectedRuleEditor(alert: Alert) {
    const ruleId = String(alert.rule_id || "").trim();
    if (!ruleId) return;
    nav(`/alerts/rules?rule_id=${encodeURIComponent(ruleId)}`);
  }

  function pivotToEvents(alert: Alert) {
    const sp = new URLSearchParams();
    const query = [alert.src_ip, alert.dst_ip, alert.mitre_technique_id, alert.rule_id]
      .filter(Boolean)
      .map((part) => String(part).trim())
      .find(Boolean);
    if (query) sp.set("search", query);
    nav(`/events${sp.toString() ? `?${sp.toString()}` : ""}`);
  }

  return {
    triaging,
    triageError,
    running,
    setRunning,
    handleTriage,
    handleTriageFieldsSave,
    copyDetailsJson,
    openRuleEditor,
    openEventsPivot,
    openSelectedRuleEditor,
    pivotToEvents,
    triageStatusAction: (status: AlertStatus) => void handleTriage({ status }),
    triageCloseAction: () =>
      triageCloseDisposition
        ? void handleTriage({ status: "closed" as AlertStatus, disposition: triageCloseDisposition as AlertDisposition })
        : undefined,
  };
}

export type AlertInvestigationActions = ReturnType<typeof useAlertInvestigationActions>;
