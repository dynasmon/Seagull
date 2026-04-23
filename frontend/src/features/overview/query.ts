export const DEFAULT_OVERVIEW_WINDOW_MINUTES = 60;

export type OverviewQueryState = {
  windowMinutes: number;
  from: string;
  to: string;
};

export type OverviewResolvedQuery = {
  windowMinutes: number;
  startTs?: string;
  endTs?: string;
  fixedRange: boolean;
  cacheKey: string;
};

export function normalizeOverviewWindowMinutes(value: unknown): number {
  const num = Number(value);
  if (!Number.isFinite(num)) return DEFAULT_OVERVIEW_WINDOW_MINUTES;
  return Math.max(5, Math.min(1440, Math.trunc(num)));
}

export function toLocalDateTimeInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mi = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
}

export function localInputToIso(value: string | null | undefined): string | undefined {
  const raw = String(value || "").trim();
  if (!raw) return undefined;
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

export function resolveOverviewQuery(state: OverviewQueryState): OverviewResolvedQuery {
  const windowMinutes = normalizeOverviewWindowMinutes(state.windowMinutes);
  const startTs = localInputToIso(state.from);
  const endTs = localInputToIso(state.to);
  const fixedRange = Boolean(startTs || endTs);
  return {
    windowMinutes,
    startTs,
    endTs,
    fixedRange,
    cacheKey: [
      `w=${windowMinutes}`,
      `s=${startTs || ""}`,
      `e=${endTs || ""}`,
    ].join("|"),
  };
}

export function durationMinutesBetween(startIso: string | null | undefined, endIso: string | null | undefined): number | null {
  if (!startIso || !endIso) return null;
  const startMs = Date.parse(startIso);
  const endMs = Date.parse(endIso);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) return null;
  return Math.max(1, Math.ceil((endMs - startMs) / 60000));
}
