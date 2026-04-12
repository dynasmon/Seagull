export function readAuditEventId(searchParams: URLSearchParams): string {
  return String(searchParams.get("event_id") || "").trim();
}

export function withAuditEventId(searchParams: URLSearchParams, eventId: string | null | undefined): URLSearchParams {
  const next = new URLSearchParams(searchParams);
  const cleanId = String(eventId || "").trim();
  if (cleanId) next.set("event_id", cleanId);
  else next.delete("event_id");
  return next;
}

