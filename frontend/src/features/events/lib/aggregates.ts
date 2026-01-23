// frontend/src/features/events/lib/aggregates.ts

export type TopCountRow = { key: string; count: number };

/**
 * Build a Top-N table from a list of string values.
 * - Ignores null/undefined/empty values
 * - Normalizes to string
 * - Returns [{key,count}] sorted by count desc, then key asc
 */
export function topCounts(values: Array<string | null | undefined>, topN = 10): TopCountRow[] {
  const m = new Map<string, number>();

  for (const v of values) {
    const s = (v ?? "").toString().trim();
    if (!s) continue;
    m.set(s, (m.get(s) || 0) + 1);
  }

  const rows: TopCountRow[] = Array.from(m.entries()).map(([key, count]) => ({ key, count }));
  rows.sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return a.key.localeCompare(b.key);
  });

  return rows.slice(0, Math.max(1, topN));
}

/**
 * Backward-compatible alias used by EventsPage.
 * Some pages import `buildTopCounts` (older name). Keep both to avoid runtime crashes.
 */
export function buildTopCounts(values: Array<string | null | undefined>, topN = 10): TopCountRow[] {
  return topCounts(values, topN);
}

function pad2(n: number) {
  return String(n).padStart(2, "0");
}

/**
 * Grafana-like compact timestamp formatting (YYYY-MM-DD HH:mm:ss).
 */
export function fmtDateTime(d: Date): string {
  const yyyy = d.getFullYear();
  const mm = pad2(d.getMonth() + 1);
  const dd = pad2(d.getDate());
  const hh = pad2(d.getHours());
  const mi = pad2(d.getMinutes());
  const ss = pad2(d.getSeconds());
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss}`;
}
