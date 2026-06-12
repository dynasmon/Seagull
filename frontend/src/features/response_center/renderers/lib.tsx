import type { ReactNode } from "react";

import { Badge } from "@/shared/components/Badge";

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = value / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(seconds)}s`;
}

const TCP_STATES: Record<string, string> = {
  "01": "ESTABLISHED",
  "02": "SYN_SENT",
  "03": "SYN_RECV",
  "04": "FIN_WAIT1",
  "05": "FIN_WAIT2",
  "06": "TIME_WAIT",
  "07": "CLOSE",
  "08": "CLOSE_WAIT",
  "09": "LAST_ACK",
  "0A": "LISTEN",
  "0B": "CLOSING",
  "0C": "NEW_SYN_RECV",
};

export function tcpStateLabel(raw: string): string {
  const key = String(raw || "").toUpperCase();
  return TCP_STATES[key] || raw || "—";
}

export function DryRunBadge() {
  return <Badge variant="info">Dry run · simulated</Badge>;
}

export function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-3">
      <div className="w-28 shrink-0 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
      <div className="min-w-0 flex-1 text-[12px] text-foreground">{children}</div>
    </div>
  );
}
