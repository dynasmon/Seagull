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

// A small palette to keep multiple series readable.
// The UI specifically asked for distinct colors per line.
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
  minWidth = 720
}: {
  data: Array<Record<string, any>>;
  seriesKeys: string[];
  /** Fixed plot height in pixels (Grafana-style panels rely on fixed heights). */
  height?: number;
  /** Minimum width (enables horizontal scrolling when the viewport is narrow). */
  minWidth?: number;
}) {
  return (
    <div className="w-full overflow-x-auto">
      <div style={{ minWidth }}>
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
                  type="monotone"
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
