import { useCallback, useEffect } from "react";

import { runAllRules } from "../api";
import { useAlertBulkActions } from "./useAlertBulkActions";
import { useAlertDrawer } from "./useAlertDrawer";
import { useAlertEvidenceModel } from "./useAlertEvidenceModel";
import { useAlertInvestigationActions } from "./useAlertInvestigationActions";
import { useAlertsData } from "./useAlertsData";
import { useAlertsFilters } from "./useAlertsFilters";
import { useAlertsQueryState } from "./useAlertsQueryState";
import type { Alert } from "../types";

export function useAlertsPageModel() {
  const query = useAlertsQueryState();
  const drawer = useAlertDrawer();
  const evidence = useAlertEvidenceModel();

  const handleAlertUpdated = useCallback(
    (alert: Alert) => {
      if (alert.id === -1) {
        drawer.closeDrawer();
        return;
      }
      drawer.updateSelected(alert);
      data.updateAlert(alert);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const data = useAlertsData(query.view, handleAlertUpdated);
  const filters = useAlertsFilters(data.alerts, query.view.search);
  const bulk = useAlertBulkActions(filters.filtered);

  useEffect(() => {
    data.setDrawerOpenRef(drawer.drawerOpen);
    data.setSelectedIdRef(drawer.selected?.id ?? null);
  }, [drawer.drawerOpen, drawer.selected, data]);

  const onCopied = useCallback(() => {
    drawer.setCopied(true);
    window.setTimeout(() => drawer.setCopied(false), 1200);
  }, [drawer]);

  const actions = useAlertInvestigationActions({
    selected: drawer.selected,
    triageNotes: drawer.triageNotes,
    triageAssignedTo: drawer.triageAssignedTo,
    triagePriority: drawer.triagePriority,
    triageRiskScore: drawer.triageRiskScore,
    triageCloseDisposition: drawer.triageCloseDisposition,
    onAlertUpdated: handleAlertUpdated,
    onCopied,
  });

  function openDrawerFor(a: Alert) {
    drawer.openDrawerFor(a);
    void evidence.loadFor(a.id);
  }

  async function handleRunAll() {
    actions.setRunning(true);
    try {
      await runAllRules();
      await data.loadHead("merge");
    } catch (e: any) {
      // error surfaced via data.error
    } finally {
      actions.setRunning(false);
    }
  }

  return {
    query,
    data,
    filters,
    bulk,
    drawer,
    evidence,
    actions,
    openDrawerFor,
    handleRunAll,
  };
}

export type AlertsPageModel = ReturnType<typeof useAlertsPageModel>;
