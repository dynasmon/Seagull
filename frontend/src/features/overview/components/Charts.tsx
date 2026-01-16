import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend
} from "recharts";

export function SimpleTimeSeries({
  data,
  seriesKeys,
  height = 220
}: {
  data: Array<Record<string, any>>;
  seriesKeys: string[];
  height?: number;
}) {
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer>
        <LineChart data={data}>
          <XAxis dataKey="t" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip />
          <Legend />
          {seriesKeys.map((k) => (
            <Line key={k} type="monotone" dataKey={k} dot={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
