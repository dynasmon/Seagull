export type AgentOnlineState = "online" | "offline" | "disabled";

export const agentDotClasses: Record<AgentOnlineState, string> = {
  online: "bg-success shadow-[0_0_10px_rgb(var(--success)/0.45)]",
  offline: "bg-warning",
  disabled: "bg-muted-foreground/50",
};

export type LatencyBand = "normal" | "attention" | "abnormal";

export const latencyBandClasses: Record<LatencyBand, string> = {
  normal: "border-success/50 bg-success/10 text-success",
  attention: "border-warning/50 bg-warning/10 text-warning",
  abnormal: "border-danger/50 bg-danger/10 text-danger",
};

export function serviceHealthClasses(state: string): string {
  const v = (state || "").toLowerCase();
  if (v === "ok") return "border-success/50 bg-success/10 text-success";
  if (v === "down") return "border-danger/50 bg-danger/10 text-danger";
  if (v === "storm") return "border-warning/50 bg-warning/10 text-warning";
  return "border-warning/40 bg-warning/10 text-warning";
}

export const inventoryStatusClasses: Record<string, string> = {
  fresh: "border-success/40 text-success bg-success/10",
  stale: "border-warning/40 text-warning bg-warning/10",
};

export function inventoryStatusBadge(status: string): string {
  return inventoryStatusClasses[status] ?? "border-danger/40 text-danger bg-danger/10";
}
