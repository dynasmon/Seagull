import type { NetEvent } from "../types";

export function eventMatchesSearch(e: NetEvent, q: string): boolean {
  const qq = (q || "").trim().toLowerCase();
  if (!qq) return true;

  const hay = [
    String(e.id),
    e.timestamp || "",
    e.agent_id || "",
    e.event_type || "",
    e.schema_version || "",
    e.src_ip || "",
    e.dst_ip || "",
    e.proto || "",
    e.src_port ? String(e.src_port) : "",
    e.dst_port ? String(e.dst_port) : "",
    typeof e.bytes === "number" ? String(e.bytes) : "",
    JSON.stringify(e.extra || {})
  ]
    .join(" ")
    .toLowerCase();

  return hay.includes(qq);
}
