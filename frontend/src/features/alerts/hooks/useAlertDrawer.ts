import { useState } from "react";

import type { Alert, AlertDisposition } from "../types";

export function useAlertDrawer() {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTab, setDrawerTab] = useState<"summary" | "evidence" | "triage" | "raw">("summary");
  const [selected, setSelected] = useState<Alert | null>(null);
  const [copied, setCopied] = useState(false);

  const [triageNotes, setTriageNotes] = useState("");
  const [triageAssignedTo, setTriageAssignedTo] = useState("");
  const [triagePriority, setTriagePriority] = useState("");
  const [triageRiskScore, setTriageRiskScore] = useState("");
  const [triageCloseDisposition, setTriageCloseDisposition] = useState<AlertDisposition | "">("");

  function openDrawerFor(a: Alert) {
    setSelected(a);
    setDrawerTab("summary");
    setDrawerOpen(true);
    setTriageNotes(a.triage_notes ?? "");
    setTriageAssignedTo(a.assigned_to ?? "");
    setTriagePriority(a.priority != null ? String(a.priority) : "");
    setTriageRiskScore(a.risk_score != null ? String(a.risk_score) : "");
    setTriageCloseDisposition((a.disposition as AlertDisposition) ?? "");
  }

  function closeDrawer() {
    setDrawerOpen(false);
  }

  function syncTriageFields(a: Alert) {
    setTriageNotes(a.triage_notes ?? "");
    setTriageAssignedTo(a.assigned_to ?? "");
    setTriagePriority(a.priority != null ? String(a.priority) : "");
    setTriageRiskScore(a.risk_score != null ? String(a.risk_score) : "");
    setTriageCloseDisposition((a.disposition as AlertDisposition) ?? "");
  }

  function updateSelected(updated: Alert) {
    setSelected((prev) => (prev && prev.id === updated.id ? updated : prev));
    syncTriageFields(updated);
  }

  function clearIfGone(id: number) {
    setSelected((prev) => {
      if (prev && prev.id === id) {
        setDrawerOpen(false);
        return null;
      }
      return prev;
    });
  }

  return {
    drawerOpen,
    drawerTab,
    setDrawerTab,
    selected,
    copied,
    setCopied,
    triageNotes,
    setTriageNotes,
    triageAssignedTo,
    setTriageAssignedTo,
    triagePriority,
    setTriagePriority,
    triageRiskScore,
    setTriageRiskScore,
    triageCloseDisposition,
    setTriageCloseDisposition,
    openDrawerFor,
    closeDrawer,
    updateSelected,
    clearIfGone,
  };
}

export type AlertDrawerController = ReturnType<typeof useAlertDrawer>;
