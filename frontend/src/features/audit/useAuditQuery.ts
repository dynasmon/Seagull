import { useEffect, useMemo, useState } from "react";

import { useDataTablePreferences } from "@/shared/hooks/useDataTablePreferences";
import { useUrlQueryState } from "@/shared/hooks/useUrlQueryState";
import { getIntParam, getStringParam, setOptionalParam } from "@/shared/lib/urlParams";

import { getAuditEvents } from "./api";
import { eventMatchesText, localInputToIso, nextUntilCursor, sortEvents } from "./lib";
import type { AuditEvent, AuditFilters } from "./types";

type Options = {
  fixedEventType?: string;
  fixedResourceType?: string;
  defaultLimit?: number;
};

type AuditQueryState = {
  limit: number;
  eventType: string;
  action: string;
  outcome: string;
  resourceType: string;
  actor: string;
  from: string;
  to: string;
  query: string;
  origin: string;
  sort: "desc" | "asc";
};

export function useAuditQuery(opts?: Options) {
  const fixedEventType = opts?.fixedEventType || "";
  const fixedResourceType = opts?.fixedResourceType || "";
  const defaultLimit = Math.max(10, Math.min(500, opts?.defaultLimit ?? 100));

  const tablePrefs = useDataTablePreferences({
    storageKey: `nw_audit_table_${fixedEventType || "all"}_${fixedResourceType || "all"}_v1`,
    defaultPageSize: defaultLimit,
    minPageSize: 10,
    maxPageSize: 500,
    defaultSort: { key: "created_at", direction: "desc" },
  });

  const [state, setState] = useUrlQueryState<AuditQueryState>({
    parse: (sp) => {
      const sort = sp.get("sort") === "asc" ? "asc" : "desc";
      return {
        limit: getIntParam(sp, "limit", { min: 10, max: 500, fallback: tablePrefs.pageSize }),
        eventType: fixedEventType || getStringParam(sp, "event_type", ""),
        action: getStringParam(sp, "action", ""),
        outcome: getStringParam(sp, "outcome", ""),
        resourceType: fixedResourceType || getStringParam(sp, "resource_type", ""),
        actor: getStringParam(sp, "actor", ""),
        from: getStringParam(sp, "from", ""),
        to: getStringParam(sp, "to", ""),
        query: sp.get("q") || "",
        origin: getStringParam(sp, "origin", ""),
        sort,
      };
    },
    serialize: (value) => {
      const sp = new URLSearchParams();
      setOptionalParam(sp, "limit", value.limit === defaultLimit ? null : value.limit);
      setOptionalParam(sp, "event_type", fixedEventType || value.eventType || null);
      setOptionalParam(sp, "action", value.action || null);
      setOptionalParam(sp, "outcome", value.outcome || null);
      setOptionalParam(sp, "resource_type", fixedResourceType || value.resourceType || null);
      setOptionalParam(sp, "actor", value.actor || null);
      setOptionalParam(sp, "from", value.from || null);
      setOptionalParam(sp, "to", value.to || null);
      setOptionalParam(sp, "q", value.query || null);
      setOptionalParam(sp, "origin", value.origin || null);
      setOptionalParam(sp, "sort", value.sort === "desc" ? null : value.sort);
      return sp;
    },
    replace: true,
  });

  useEffect(() => {
    if (tablePrefs.pageSize !== state.limit) tablePrefs.setPageSize(state.limit);
  }, [state.limit, tablePrefs]);

  useEffect(() => {
    if (tablePrefs.sort?.direction === state.sort) return;
    tablePrefs.setSort({ key: "created_at", direction: state.sort });
  }, [state.sort, tablePrefs]);

  const filters = useMemo<AuditFilters>(() => {
    return {
      limit: state.limit,
      eventType: fixedEventType || state.eventType,
      action: state.action,
      outcome: state.outcome,
      resourceType: fixedResourceType || state.resourceType,
      actor: state.actor,
      from: state.from,
      to: state.to,
      query: state.query,
      origin: state.origin,
      sort: state.sort,
    };
  }, [fixedEventType, fixedResourceType, state]);

  function setFilter(name: keyof AuditFilters, value: string | number) {
    setState((prev) => {
      const next: AuditQueryState = { ...prev };

      if (name === "limit") {
        const limit = Math.max(10, Math.min(500, Math.trunc(Number(value) || defaultLimit)));
        tablePrefs.setPageSize(limit);
        next.limit = limit;
        return next;
      }

      if (name === "sort") {
        const sort = value === "asc" ? "asc" : "desc";
        tablePrefs.setSort({ key: "created_at", direction: sort });
        next.sort = sort;
        return next;
      }

      const stringValue = String(value || "").trim();
      if (name === "eventType") next.eventType = stringValue;
      else if (name === "resourceType") next.resourceType = stringValue;
      else if (name === "actor") next.actor = stringValue;
      else if (name === "query") next.query = String(value || "");
      else if (name === "action") next.action = stringValue;
      else if (name === "outcome") next.outcome = stringValue;
      else if (name === "from") next.from = stringValue;
      else if (name === "to") next.to = stringValue;
      else if (name === "origin") next.origin = stringValue;

      if (fixedEventType) next.eventType = fixedEventType;
      if (fixedResourceType) next.resourceType = fixedResourceType;
      return next;
    });
  }

  function resetFilters() {
    tablePrefs.setPageSize(defaultLimit);
    tablePrefs.setSort({ key: "created_at", direction: "desc" });

    setState({
      limit: defaultLimit,
      eventType: fixedEventType,
      action: "",
      outcome: "",
      resourceType: fixedResourceType,
      actor: "",
      from: "",
      to: "",
      query: "",
      origin: "",
      sort: "desc",
    });
  }

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<AuditEvent[]>([]);
  const [hasMore, setHasMore] = useState(false);

  const [page, setPage] = useState(1);
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);

  const serverQuerySignature = useMemo(
    () =>
      JSON.stringify({
        limit: filters.limit,
        eventType: filters.eventType,
        action: filters.action,
        outcome: filters.outcome,
        resourceType: filters.resourceType,
        actor: filters.actor,
        from: filters.from,
        to: filters.to,
      }),
    [filters.action, filters.actor, filters.eventType, filters.from, filters.limit, filters.outcome, filters.resourceType, filters.to]
  );

  useEffect(() => {
    setPage(1);
    setCursors([localInputToIso(filters.to)]);
  }, [serverQuerySignature, filters.to]);

  async function reload() {
    const untilCursor = cursors[page - 1] || localInputToIso(filters.to);

    setLoading(true);
    setError(null);
    try {
      const out = await getAuditEvents({
        limit: filters.limit,
        event_type: filters.eventType || undefined,
        action: filters.action || undefined,
        outcome: filters.outcome || undefined,
        resource_type: filters.resourceType || undefined,
        actor_username: filters.actor || undefined,
        since: localInputToIso(filters.from),
        until: untilCursor,
      });

      const fetched = out.items || [];
      setRows(fetched);
      setHasMore(Boolean(out.has_more));

      const nxt = out.has_more ? nextUntilCursor(fetched) : undefined;
      setCursors((prev) => {
        const cloned = [...prev];
        cloned[page] = nxt;
        return cloned;
      });
    } catch (e: any) {
      setError(e?.message || "Failed to load audit events");
      setRows([]);
      setHasMore(false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, serverQuerySignature]);

  const filteredRows = useMemo(() => {
    const byText = rows.filter((r) => eventMatchesText(r, filters.query, filters.origin));
    return sortEvents(byText, filters.sort);
  }, [filters.origin, filters.query, filters.sort, rows]);

  function nextPage() {
    if (!hasMore) return;
    const canGo = Boolean(cursors[page]);
    if (!canGo) return;
    setPage((p) => p + 1);
  }

  function prevPage() {
    setPage((p) => Math.max(1, p - 1));
  }

  return {
    filters,
    setFilter,
    resetFilters,
    loading,
    error,
    rows,
    visibleRows: filteredRows,
    hasMore,
    page,
    reload,
    nextPage,
    prevPage,
    hasPrev: page > 1,
  };
}
