function isNoDataValue(v: unknown): boolean {
  if (v === null || v === undefined) return true;

  if (typeof v === "number") {
    if (!Number.isFinite(v)) return true;
    return v === 0;
  }

  const n = Number(v);
  if (Number.isFinite(n)) return n === 0;

  return true;
}

export function maskTrailingNoDataBuckets<T extends Record<string, unknown>>(
  data: T[],
  seriesKeys: string[]
): T[] {
  if (!Array.isArray(data) || data.length === 0) return data;

  const lastIdxByKey: Record<string, number> = {};
  for (const k of seriesKeys) lastIdxByKey[k] = -1;

  for (let i = 0; i < data.length; i++) {
    const row = data[i] || {};
    for (const k of seriesKeys) {
      if (!isNoDataValue(row[k])) lastIdxByKey[k] = i;
    }
  }

  const out = new Array(data.length) as T[];

  for (let i = 0; i < data.length; i++) {
    const row = data[i] || ({} as T);
    let changed = false;
    let nextRow: T | null = null;

    for (const k of seriesKeys) {
      const last = lastIdxByKey[k];
      const shouldNull = last === -1 ? true : i > last;

      if (shouldNull && row[k] !== null) {
        if (!changed) {
          nextRow = { ...row };
          changed = true;
        }
        (nextRow as Record<string, unknown>)[k] = null;
      }
    }

    out[i] = changed ? (nextRow as T) : row;
  }

  return out;
}
