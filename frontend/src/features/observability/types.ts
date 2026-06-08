export type ObservabilityStatus = {
  enabled: boolean;
  available: boolean;
};

export type CatalogueItem = {
  key: string;
  title: string;
  description: string;
  unit: string;
  kinds: string[];
  requires_window: boolean;
};

export type CatalogueResponse = {
  queries: CatalogueItem[];
};

export type InstantSample = {
  metric: Record<string, string>;
  value: number | null;
  timestamp: number | null;
};

export type RangePoint = [number, number | null];

export type RangeSeries = {
  metric: Record<string, string>;
  points: RangePoint[];
};

export type QueryResult = {
  key: string;
  title: string;
  unit: string;
  kind: "instant" | "range";
  result_type: string;
  samples?: InstantSample[];
  series?: RangeSeries[];
};

export type QueryEnvelope = {
  available: boolean;
  error: string | null;
  result: QueryResult | null;
};

export type EnvelopeMap = Record<string, QueryEnvelope>;
