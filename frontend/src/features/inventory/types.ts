export type PackageEntry = {
  name: string;
  version: string;
  arch?: string | null;
};

export type InventorySnapshotOut = {
  id: number;
  agent_id: string;
  collected_at: string;
  schema_version: number;
  os: Record<string, any>;
  packages: PackageEntry[];
  packages_hash: string;
  packages_count: number;
  manager?: string | null;
  extra: Record<string, any>;
};

export type TimeSeries = {
  series: string[];
  data: Array<Record<string, any>>;
};

export type InventoryKPIs = {
  agents_total: number;
  agents_online_5m: number;
  agents_with_inventory_6h: number;
  oldest_inventory_age_minutes: number;
};

export type InventoryAgeItem = { metric: string; value: number };

export type InventoryWarningRow = {
  time: string | null;
  agent_id: string;
  warning: string;
};

export type FleetHealthRow = {
  agent_id: string;
  last_seen_at: string | null;
  last_seen_age_min: number;
  last_inventory_at: string | null;
  inventory_age_min: number | null;
  inventory_status: "fresh" | "stale" | "no_inventory";
  os: string;
  manager: string;
  packages_count: number | null;
  packages_hash: string | null;
  warnings_count: number;
  is_revoked: boolean;
};

export type InventoryChangeRow = {
  time: string | null;
  agent_id: string;
  change_type: "baseline" | "changed" | "unchanged";
  old_hash: string | null;
  new_hash: string | null;
  old_count: number | null;
  new_count: number | null;
};

export type InventoryOverviewSnapshot = {
  agent_id: string;
  window_minutes: number;
  kpis: InventoryKPIs;

  snapshots_per_minute: TimeSeries;
  changes_per_10m: TimeSeries;

  os_distribution: Array<{ os: string; agents: number }>;
  manager_distribution: Array<{ manager: string; agents: number }>;

  inventory_age_by_agent: InventoryAgeItem[];
  packages_count_by_agent: InventoryAgeItem[];

  recent_warnings: InventoryWarningRow[];
  fleet_health: FleetHealthRow[];
  recent_changes: InventoryChangeRow[];
};
