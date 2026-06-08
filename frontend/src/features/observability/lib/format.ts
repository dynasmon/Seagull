const compactFmt = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });

export function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

export function formatCompact(value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (Math.abs(value) < 1000) {
    return Number.isInteger(value) ? String(value) : value.toFixed(value < 10 ? 2 : 1);
  }
  return compactFmt.format(value);
}

export function formatRate(value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (value === 0) return "0";
  if (Math.abs(value) < 1) return value.toFixed(3);
  if (Math.abs(value) < 100) return value.toFixed(2);
  return compactFmt.format(value);
}

export function formatPercent(ratio: number): string {
  if (!Number.isFinite(ratio)) return "—";
  const pct = ratio * 100;
  if (pct === 0) return "0%";
  if (pct < 0.01) return "<0.01%";
  return `${pct < 10 ? pct.toFixed(2) : pct.toFixed(1)}%`;
}

export function formatMs(value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (value < 1) return `${value.toFixed(2)} ms`;
  return `${Math.round(value)} ms`;
}

export function formatSeconds(value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (value < 1) return `${Math.round(value * 1000)} ms`;
  return `${value.toFixed(2)} s`;
}

export function formatByUnit(unit: string, value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  switch (unit) {
    case "ops":
      return `${formatRate(value)}/s`;
    case "ratio":
      return formatPercent(value);
    case "ms":
      return formatMs(value);
    case "seconds":
      return formatSeconds(value);
    case "bool":
      return value >= 0.5 ? "Active" : "Idle";
    case "count":
    default:
      return formatCompact(value);
  }
}

export function unitBadge(unit: string): string {
  switch (unit) {
    case "ops":
      return "per sec";
    case "ratio":
      return "ratio";
    case "ms":
      return "ms";
    case "seconds":
      return "seconds";
    case "bool":
      return "state";
    case "count":
    default:
      return "count";
  }
}

export function axisFormatterFor(unit: string): (value: number) => string {
  switch (unit) {
    case "ratio":
      return (v) => formatPercent(v);
    case "ms":
      return (v) => (v >= 1000 ? compactFmt.format(v) : String(Math.round(v)));
    case "seconds":
      return (v) => (v < 1 ? `${Math.round(v * 1000)}ms` : `${v.toFixed(v < 10 ? 1 : 0)}s`);
    default:
      return (v) => formatCompact(v);
  }
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

export function timeLabel(epochSeconds: number): string {
  const d = new Date(epochSeconds * 1000);
  if (Number.isNaN(d.getTime())) return String(epochSeconds);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function clockLabel(date: Date | null): string {
  if (!date) return "—";
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
