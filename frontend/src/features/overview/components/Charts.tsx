import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid
} from "recharts";

/**
 * Default color palette for time series lines.
 * (If you already have a palette elsewhere, you can keep yours.)
 */
const DEFAULT_PALETTE = [
  "#22d3ee",
  "#a78bfa",
  "#34d399",
  "#fbbf24",
  "#fb7185",
  "#60a5fa",
  "#f472b6",
  "#cbd5e1"
];

/**
 * Special-case strokes for known keys (e.g., severity charts),
 * falling back to the default palette when not matched.
 */
const SEVERITY_STROKES: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  unknown: "#94a3b8",
  failures: "#ef4444"
};

function pickStroke(key: string, idx: number): string {
  const k = (key || "").toLowerCase();
  return SEVERITY_STROKES[k] || DEFAULT_PALETTE[idx % DEFAULT_PALETTE.length];
}

/**
 * Grafana-like behavior requirement:
 * - The X-axis (time buckets) must keep moving to the right up to "now".
 * - The line must stop at the last real datapoint and remain blank afterwards.
 *
 * How we do it in Recharts:
 * - We KEEP the full timeline rows.
 * - We convert trailing "no data" buckets into `null` values, so the line is not drawn.
 *
 * Project heuristic:
 * - The backend often generates buckets up to now (e.g., generate_series) and fills missing
 *   buckets with 0 (or null). For trailing buckets, 0 usually means "no data".
 *
 * NOTE:
 * If any chart has real zeros that must be drawn as data, we can add a per-chart flag later
 * (e.g., treatZeroAsNoData=false). For now this is global as requested.
 */
function isNoDataValue(v: any): boolean {
  if (v === null || v === undefined) return true;

  if (typeof v === "number") {
    if (!Number.isFinite(v)) return true;
    return v === 0;
  }

  // Handle numeric strings, etc.
  const n = Number(v);
  if (Number.isFinite(n)) return n === 0;

  return true;
}

/**
 * For each series key, find the last index that contains a real datapoint.
 * For buckets AFTER that index, set that series value to `null`.
 *
 * This keeps the full time range on the axis while making the line stop where data ends.
 */
function maskTrailingNoDataBuckets(
  data: Array<Record<string, any>>,
  seriesKeys: string[]
): Array<Record<string, any>> {
  if (!Array.isArray(data) || data.length === 0) return data;

  // Last non-empty index per series key.
  const lastIdxByKey: Record<string, number> = {};
  for (const k of seriesKeys) lastIdxByKey[k] = -1;

  for (let i = 0; i < data.length; i++) {
    const row = data[i] || {};
    for (const k of seriesKeys) {
      if (!isNoDataValue(row[k])) lastIdxByKey[k] = i;
    }
  }

  // Build output with minimal copying (only clone rows when needed).
  const out: Array<Record<string, any>> = new Array(data.length);

  for (let i = 0; i < data.length; i++) {
    const row = data[i] || {};
    let changed = false;
    let nextRow: Record<string, any> | null = null;

    for (const k of seriesKeys) {
      const last = lastIdxByKey[k];

      // If a series never had real data, make it null everywhere.
      // If i is after the last real point, null it to stop the line.
      const shouldNull = last === -1 ? true : i > last;

      if (shouldNull && row[k] !== null) {
        if (!changed) {
          nextRow = { ...row };
          changed = true;
        }
        nextRow![k] = null;
      }
    }

    out[i] = changed ? (nextRow as Record<string, any>) : row;
  }

  return out;
}

export function SimpleTimeSeries({
  data,
  seriesKeys,
  height = 220,
  minWidth = 720,
  allowHorizontalScroll = true
}: {
  data: Array<Record<string, any>>;
  seriesKeys: string[];
  height?: number;
  minWidth?: number;
  allowHorizontalScroll?: boolean;
}) {
  // Keep full timeline, but stop drawing each line after its last real datapoint.
  const maskedData = maskTrailingNoDataBuckets(data, seriesKeys);

  return (
    <div className={allowHorizontalScroll ? "w-full min-w-0 overflow-x-auto" : "w-full min-w-0 overflow-hidden"}>
      <div
        style={
          allowHorizontalScroll
            ? { minWidth, width: "100%", minHeight: height }
            : { width: "100%", minWidth: 0, minHeight: height }
        }
      >
        {/*
          Recharts can emit width/height <= 0 warnings when containers momentarily measure to 0
          during layout. We keep explicit minWidth/minHeight to avoid negative/zero measurements.
        */}
        <div style={{ width: "100%", height, minWidth: 1, minHeight: 1 }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={maskedData}>
              <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
              <XAxis dataKey="t" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Legend />

              {seriesKeys.map((k, idx) => (
                <Line
                  key={k}
                  type="linear"
                  dataKey={k}
                  dot={false}
                  strokeWidth={2}
                  isAnimationActive={false}
                  // Do not connect gaps; null values break/stop the line like Grafana.
                  connectNulls={false}
                  stroke={pickStroke(k, idx)}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
