import type { HygieneDomain, InventoryWarningRow, InventoryChangeRow, FleetHealthRow } from "./types";

export const EMPTY_WARNING_ROWS: InventoryWarningRow[] = [];
export const EMPTY_CHANGE_ROWS: InventoryChangeRow[] = [];
export const EMPTY_FLEET_ROWS: FleetHealthRow[] = [];

export const HYGIENE_TABS: Array<{ key: HygieneDomain; label: string }> = [
  { key: "dashboard", label: "Dashboard" },
  { key: "system", label: "System" },
  { key: "software", label: "Software" },
  { key: "processes", label: "Processes" },
  { key: "network", label: "Network" },
  { key: "identity", label: "Identity" },
  { key: "services", label: "Services" },
];

export const DOMAIN_HINT: Record<HygieneDomain, string> = {
  dashboard: "Cross-agent hygiene baseline with fleet freshness and drift.",
  system: "Operating system posture, inventory freshness, and host baselines.",
  software: "Package manager distributions, package drift, and baseline deltas.",
  processes: "Process/runtime-oriented signals from inventory warnings and endpoint pivots.",
  network: "Endpoint network-facing inventory drift and warning pivots.",
  identity: "Identity and metadata hygiene with fast asset pivot controls.",
  services: "Service-level hygiene surfaced through warnings and inventory pivots.",
};
