export type Density = "comfortable" | "compact";

export type ViewCfg = {
  severity: string;
  status: string;
  rule_id: string;
  agent_id: string;
  search: string;
  page_size: number;
  infinite_scroll: boolean;
  wrap_json: boolean;
  density: Density;
};

export const LS_KEY = "nw_alerts_queue_view_v1";

export const DEFAULTS: ViewCfg = {
  severity: "all",
  status: "all",
  rule_id: "",
  agent_id: "",
  search: "",
  page_size: 200,
  infinite_scroll: false,
  wrap_json: true,
  density: "compact",
};

export const ALERTS_RT_FLUSH_MS = 220;
export const ALERTS_RT_BURST_WINDOW_MS = 1000;
export const ALERTS_RT_BURST_LIMIT = 80;

export const ALL_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
