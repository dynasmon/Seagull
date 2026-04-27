import { ExposureAssetSort, ExposureSeverity, ExposureStatus } from "./types";

export type AssetFilters = {
  q: string;
  severity: ExposureSeverity | "";
  min_score: number | null;
  agent_id: string;
  reason_code: string;
  status: ExposureStatus | "";
  sort: ExposureAssetSort;
  has_attack_chain: boolean | null;
  has_critical_vuln: boolean | null;
  has_persistence_signal: boolean | null;
};

export type PathFilters = {
  severity: ExposureSeverity | "";
  min_score: number | null;
};

export type FindingFilters = {
  severity: ExposureSeverity | "";
  finding_type: string;
  status: string;
  q: string;
};

export const DEFAULT_ASSET_FILTERS: AssetFilters = {
  q: "",
  severity: "",
  min_score: null,
  agent_id: "",
  reason_code: "",
  status: "",
  sort: "risk_desc",
  has_attack_chain: null,
  has_critical_vuln: null,
  has_persistence_signal: null,
};

export const DEFAULT_PATH_FILTERS: PathFilters = {
  severity: "",
  min_score: null,
};

export const DEFAULT_FINDING_FILTERS: FindingFilters = {
  severity: "",
  finding_type: "",
  status: "",
  q: "",
};

export const SEVERITY_OPTIONS: Array<{ value: ExposureSeverity | ""; label: string }> = [
  { value: "", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "informational", label: "Informational" },
];

export const SORT_OPTIONS: Array<{ value: ExposureAssetSort; label: string }> = [
  { value: "risk_desc", label: "Highest risk" },
  { value: "risk_asc", label: "Lowest risk" },
  { value: "updated_desc", label: "Recently updated" },
  { value: "last_seen_desc", label: "Recently seen" },
];

export const ASSET_STATUS_OPTIONS: Array<{ value: ExposureStatus | ""; label: string }> = [
  { value: "", label: "All statuses" },
  { value: "active", label: "Active" },
  { value: "stale", label: "Stale" },
  { value: "inactive", label: "Inactive" },
  { value: "unknown", label: "Unknown" },
];

export const FINDING_STATUS_OPTIONS = [
  { value: "", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "resolved", label: "Resolved" },
  { value: "suppressed", label: "Suppressed" },
];
