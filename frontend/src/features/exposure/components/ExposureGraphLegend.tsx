import { ExposureGraphLegend as LegendData } from "../types";
import { severityColor } from "../graphLayout";

type Props = {
  legend: LegendData;
};

const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"];

export function ExposureGraphLegend({ legend }: Props) {
  return (
    <div className="flex flex-wrap gap-6 text-xs">
      {legend.node_types.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Node Types
          </div>
          <ul className="space-y-1">
            {legend.node_types.map((item) => (
              <li key={item.key} className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-foreground/40" />
                {item.label}
              </li>
            ))}
          </ul>
        </div>
      )}

      {legend.edge_types.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Edge Types
          </div>
          <ul className="space-y-1">
            {legend.edge_types.map((item) => (
              <li key={item.key} className="flex items-center gap-1.5">
                <span className="h-px w-4 bg-foreground/40" />
                {item.label}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Severity
        </div>
        <ul className="space-y-1">
          {SEVERITY_LEVELS.map((s) => (
            <li key={s} className="flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: severityColor(s) }}
              />
              <span className="capitalize">{s}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
