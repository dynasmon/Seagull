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
  // IMPORTANT:
  // - allowHorizontalScroll=true: wrapper is scrollable (overflow-x-auto)
  // - allowHorizontalScroll=false: wrapper is strictly clipped (overflow-hidden) to prevent scrollbars/flickering
  return (
    <div className={allowHorizontalScroll ? "w-full overflow-x-auto" : "w-full overflow-hidden"}>
      <div style={allowHorizontalScroll ? { minWidth } : { width: "100%" }}>
        <div style={{ width: "100%", height }}>
          <ResponsiveContainer>
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
              <XAxis dataKey="t" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Legend />
              {seriesKeys.map((k, idx) => (
                <Line
                  key={k}
                  // CHANGE: "linear" makes lines straight (Grafana style) instead of curved ("monotone")
                  type="linear"
                  dataKey={k}
                  dot={false}
                  strokeWidth={2}
                  isAnimationActive={false}
                  connectNulls
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