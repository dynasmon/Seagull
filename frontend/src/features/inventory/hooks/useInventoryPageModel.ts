import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";

import { useInventoryUrlState } from "./useInventoryUrlState";
import { useInventoryOverview } from "./useInventoryOverview";
import { useInventoryDerivedData } from "./useInventoryDerivedData";
import { useInventoryDrawer } from "./useInventoryDrawer";

export function useInventoryPageModel() {
  const urlState = useInventoryUrlState();

  const overview = useInventoryOverview({
    agentScope: urlState.agentScope,
    windowMinutes: urlState.windowMinutes,
  });

  const derived = useInventoryDerivedData({
    snapshot: overview.snapshot,
    agentScope: urlState.agentScope,
    domain: urlState.domain,
  });

  const drawer = useInventoryDrawer({
    urlAgentId: urlState.urlAgentId,
    urlSnapshotId: urlState.urlSnapshotId,
    urlOpenDrawer: urlState.urlOpenDrawer,
  });

  const tablePrefs = useDataTablePreferences({
    storageKey: "nw_inventory_tables_v2",
    defaultPageSize: 100,
    minPageSize: 25,
    maxPageSize: 200,
    defaultCompact: true,
  });

  return {
    urlState,
    overview,
    derived,
    drawer,
    compact: tablePrefs.compact,
    setCompact: tablePrefs.setCompact,
  };
}

export type InventoryPageModel = ReturnType<typeof useInventoryPageModel>;
