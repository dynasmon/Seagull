import { memo, useEffect, useMemo, useRef, useState } from "react";

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

function isNoDataValue(v: any): boolean {
  if (v === null || v === undefined) return true;

  if (typeof v === "number") {
    if (!Number.isFinite(v)) return true;
    return v === 0;
  }

  const n = Number(v);
  if (Number.isFinite(n)) return n === 0;

  return true;
}

function maskTrailingNoDataBuckets(
  data: Array<Record<string, any>>,
  seriesKeys: string[]
): Array<Record<string, any>> {
  if (!Array.isArray(data) || data.length === 0) return data;

  const lastIdxByKey: Record<string, number> = {};
  for (const k of seriesKeys) lastIdxByKey[k] = -1;

  for (let i = 0; i < data.length; i++) {
    const row = data[i] || {};
    for (const k of seriesKeys) {
      if (!isNoDataValue(row[k])) lastIdxByKey[k] = i;
    }
  }

  const out: Array<Record<string, any>> = new Array(data.length);

  for (let i = 0; i < data.length; i++) {
    const row = data[i] || {};
    let changed = false;
    let nextRow: Record<string, any> | null = null;

    for (const k of seriesKeys) {
      const last = lastIdxByKey[k];
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

export const SimpleTimeSeries = memo(function SimpleTimeSeries({
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
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [chartSize, setChartSize] = useState({ width: 0, height: 0 });
  const canRenderChart = chartSize.width > 1 && chartSize.height > 1;

  useEffect(() => {
    const el = mountRef.current;
    if (!el) return;
    let frame = 0;

    const update = () => {
      const rect = el.getBoundingClientRect();
      setChartSize((prev) => {
        const width = Math.round(rect.width);
        const heightPx = Math.round(rect.height);
        if (prev.width === width && prev.height === heightPx) return prev;
        return { width, height: heightPx };
      });
    };

    frame = window.requestAnimationFrame(update);
    if (typeof ResizeObserver === "undefined") {
      return () => {
        window.cancelAnimationFrame(frame);
      };
    }

    const observer = new ResizeObserver(() => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(update);
    });
    observer.observe(el);
    return () => {
      window.cancelAnimationFrame(frame);
      observer.disconnect();
    };
  }, [height, allowHorizontalScroll, minWidth]);

  const maskedData = useMemo(
    () => maskTrailingNoDataBuckets(data, seriesKeys),
    [data, seriesKeys]
  );

  return (
    <div className={allowHorizontalScroll ? "w-full min-w-0 overflow-x-auto" : "w-full min-w-0 overflow-hidden"}>
      <div
        style={
          allowHorizontalScroll
            ? { minWidth, width: "100%", minHeight: height }
            : { width: "100%", minWidth: 0, minHeight: height }
        }
      >
        <div ref={mountRef} style={{ width: "100%", height, minWidth: 1, minHeight: 1 }}>
          {canRenderChart ? (
            <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1} debounce={80}>
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
                    connectNulls={false}
                    stroke={pickStroke(k, idx)}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : null}
        </div>
      </div>
    </div>
  );
});
