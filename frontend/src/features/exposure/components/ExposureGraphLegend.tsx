import { ExposureGraphLegend as LegendData } from "../types";
import { exposureEdgeLabel, exposureNodeLabel } from "../utils";

type Props = {
  legend: LegendData;
};

const CORE_NODE_TYPES = [
  "asset",
  "service",
  "package",
  "cve",
  "ip",
  "process",
  "file",
  "alert",
  "attack_chain_case",
  "investigation",
  "response_action",
];

const NODE_SWATCHES: Record<string, string> = {
  asset: "bg-primary",
  service: "bg-info",
  package: "bg-warning",
  cve: "bg-danger",
  ip: "bg-info",
  process: "bg-warning",
  file: "bg-success",
  alert: "bg-danger",
  attack_chain_case: "bg-danger",
  investigation: "bg-primary",
  response_action: "bg-success",
};

const EDGE_SAMPLES = ["has_service", "has_cve", "triggered_alert", "part_of_attack_chain", "part_of_investigation", "triggered_response_action"];

export function ExposureGraphLegend({ legend }: Props) {
  const availableNodeTypes = new Map(legend.node_types.map((item) => [item.key, item.label]));
  const availableEdgeTypes = new Map(legend.edge_types.map((item) => [item.key, item.label]));

  const nodeItems = CORE_NODE_TYPES.filter((key) => availableNodeTypes.has(key) || NODE_SWATCHES[key]).map((key) => ({
    key,
    label: key === "cve" ? "Vulnerability" : key === "ip" ? "Source IP" : availableNodeTypes.get(key) || exposureNodeLabel(key),
  }));

  const edgeItems = EDGE_SAMPLES.map((key) => ({
    key,
    label: availableEdgeTypes.get(key) || exposureEdgeLabel(key),
  }));

  return (
    <div className="grid gap-4 lg:grid-cols-[1.4fr,1fr]">
      <div className="rounded-lg border border-border/60 bg-background/30 p-4">
        <div className="mb-3 text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">
          Node meaning
        </div>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {nodeItems.map((item) => (
            <div key={item.key} className="flex items-center gap-2 rounded-md border border-border/50 bg-background/35 px-3 py-2 text-[12px]">
              <span className={`h-2.5 w-2.5 rounded-full ${NODE_SWATCHES[item.key] || "bg-muted-foreground"}`} />
              <span>{item.label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-border/60 bg-background/30 p-4">
        <div className="mb-3 text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">
          Edge meaning
        </div>
        <div className="space-y-2">
          {edgeItems.map((item) => (
            <div key={item.key} className="flex items-center gap-3 rounded-md border border-border/50 bg-background/35 px-3 py-2 text-[12px]">
              <span className="h-px w-7 bg-muted-foreground/70" />
              <span>{item.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
