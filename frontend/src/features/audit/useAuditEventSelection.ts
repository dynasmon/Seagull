import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import type { AuditEvent } from "@/features/audit/types";
import { readAuditEventId, withAuditEventId } from "@/features/audit/urlState";

export function useAuditEventSelection(rows: AuditEvent[]) {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedEventId = readAuditEventId(searchParams);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  useEffect(() => {
    if (!selectedEventId) {
      setSelectedEvent(null);
      return;
    }
    const matched = rows.find((row) => row.id === selectedEventId);
    setSelectedEvent(matched || null);
  }, [rows, selectedEventId]);

  const openEvent = useCallback(
    (event: AuditEvent) => {
      setSelectedEvent(event);
      setSearchParams((prev) => withAuditEventId(prev, event.id), { replace: true });
    },
    [setSearchParams]
  );

  const closeEvent = useCallback(() => {
    setSelectedEvent(null);
    setSearchParams((prev) => withAuditEventId(prev, null), { replace: true });
  }, [setSearchParams]);

  return useMemo(
    () => ({
      selectedEventId,
      selectedEvent,
      openEvent,
      closeEvent,
    }),
    [closeEvent, openEvent, selectedEvent, selectedEventId]
  );
}

export default useAuditEventSelection;
