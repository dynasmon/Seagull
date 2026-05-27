import { useRef, useState } from "react";

import { getAlertEvidence } from "../api";
import type { AlertEvidenceItem } from "../types";

export function useAlertEvidenceModel() {
  const [evidenceItems, setEvidenceItems] = useState<AlertEvidenceItem[]>([]);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const evidenceAlertIdRef = useRef<number | null>(null);

  async function loadFor(alertId: number) {
    if (evidenceAlertIdRef.current === alertId) return;
    evidenceAlertIdRef.current = alertId;
    setEvidenceItems([]);
    setEvidenceLoading(true);
    try {
      const items = await getAlertEvidence(alertId);
      if (evidenceAlertIdRef.current === alertId) {
        setEvidenceItems(items);
      }
    } catch {
      if (evidenceAlertIdRef.current === alertId) setEvidenceItems([]);
    } finally {
      if (evidenceAlertIdRef.current === alertId) setEvidenceLoading(false);
    }
  }

  return { evidenceItems, evidenceLoading, loadFor };
}

export type AlertEvidenceModel = ReturnType<typeof useAlertEvidenceModel>;
