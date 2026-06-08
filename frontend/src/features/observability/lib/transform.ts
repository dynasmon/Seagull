import type { ChartPanelSpec } from "./panels";
import type { EnvelopeMap, QueryEnvelope, RangeSeries } from "../types";
import { isFiniteNumber, timeLabel } from "./format";

export type ChartData = {
  rows: Array<Record<string, unknown>>;
  seriesKeys: string[];
  seriesNames: Record<string, string>;
  isEmpty: boolean;
};

function seriesLabel(series: RangeSeries): string | null {
  const values = Object.values(series.metric || {}).filter((v) => v !== "" && v !== "none");
  if (!values.length) return null;
  return values.join(" / ");
}

export function buildChartData(panel: ChartPanelSpec, envelopes: EnvelopeMap): ChartData {
  const seriesKeys: string[] = [];
  const seriesNames: Record<string, string> = {};
  const rowMap = new Map<number, Record<string, unknown>>();

  for (const spec of panel.keys) {
    const result = envelopes[spec.key]?.result;
    if (!result || result.kind !== "range" || !Array.isArray(result.series)) continue;
    for (const series of result.series) {
      const split = seriesLabel(series);
      const seriesId = split ? `${spec.key}::${split}` : spec.key;
      const name = split ?? spec.label;
      if (!(seriesId in seriesNames)) {
        seriesKeys.push(seriesId);
        seriesNames[seriesId] = name;
      }
      for (const [ts, value] of series.points) {
        let row = rowMap.get(ts);
        if (!row) {
          row = { t: timeLabel(ts), _ts: ts };
          rowMap.set(ts, row);
        }
        row[seriesId] = isFiniteNumber(value) ? value : null;
      }
    }
  }

  const rows = Array.from(rowMap.values()).sort((a, b) => Number(a._ts) - Number(b._ts));
  for (const row of rows) {
    for (const key of seriesKeys) {
      if (!(key in row)) row[key] = null;
    }
  }

  const hasSignal = rows.some((row) => seriesKeys.some((key) => isFiniteNumber(row[key])));
  return { rows, seriesKeys, seriesNames, isEmpty: seriesKeys.length === 0 || !hasSignal };
}

export function latestValue(env: QueryEnvelope | undefined): number | null {
  const result = env?.result;
  if (!result) return null;
  if (result.kind === "instant" && Array.isArray(result.samples)) {
    const sample = result.samples.find((s) => isFiniteNumber(s.value));
    return sample ? (sample.value as number) : null;
  }
  if (result.kind === "range" && Array.isArray(result.series)) {
    let best: number | null = null;
    let bestTs = -Infinity;
    for (const series of result.series) {
      for (let i = series.points.length - 1; i >= 0; i -= 1) {
        const [ts, value] = series.points[i];
        if (!isFiniteNumber(value)) continue;
        if (ts > bestTs) {
          bestTs = ts;
          best = value;
        }
        break;
      }
    }
    return best;
  }
  return null;
}
