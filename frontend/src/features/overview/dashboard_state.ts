export function timeSeriesHasSignal(
  rows: Array<Record<string, unknown>> | null | undefined,
  ignoreKeys: readonly string[] = ["t"],
): boolean {
  if (!Array.isArray(rows) || rows.length === 0) return false;
  const ignored = new Set(ignoreKeys);
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    for (const [key, value] of Object.entries(row)) {
      if (ignored.has(key)) continue;
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) continue;
      if (numeric > 0) return true;
    }
  }
  return false;
}
