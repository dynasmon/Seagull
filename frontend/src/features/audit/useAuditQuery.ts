import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { getAuditEvents } from "./api";
import { eventMatchesText, localInputToIso, nextUntilCursor, sortEvents } from "./lib";
import type { AuditEvent, AuditFilters } from "./types";

type Options = {
  fixedEventType?: string;
  fixedResourceType?: string;
  defaultLimit?: number;
};

function parseLimit(raw: string | null, def: number): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return def;
  return Math.max(10, Math.min(500, Math.trunc(n)));
}

export function useAuditQuery(opts?: Options) {
  const fixedEventType = opts?.fixedEventType || "";
  const fixedResourceType = opts?.fixedResourceType || "";
  const defaultLimit = Math.max(10, Math.min(500, opts?.defaultLimit ?? 100));

  const [sp, setSp] = useSearchParams();

  const filters = useMemo<AuditFilters>(() => {
    return {
      limit: parseLimit(sp.get("limit"), defaultLimit),
      eventType: fixedEventType || (sp.get("event_type") || ""),
      action: sp.get("action") || "",
      outcome: sp.get("outcome") || "",
      resourceType: fixedResourceType || (sp.get("resource_type") || ""),
      actor: sp.get("actor") || "",
      from: sp.get("from") || "",
      to: sp.get("to") || "",
      query: sp.get("q") || "",
      origin: sp.get("origin") || "",
      sort: (sp.get("sort") === "asc" ? "asc" : "desc"),
    };
  }, [defaultLimit, fixedEventType, fixedResourceType, sp]);

  function setFilter(name: keyof AuditFilters, value: string | number) {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      const v = String(value || "").trim();

      const key =
        name === "eventType"
          ? "event_type"
          : name === "resourceType"
            ? "resource_type"
            : name === "actor"
              ? "actor"
              : name === "query"
                ? "q"
                : name;

      if (!v) next.delete(key);
      else next.set(key, v);

      return next;
    });
  }

  function resetFilters() {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const k of ["limit", "event_type", "action", "outcome", "resource_type", "actor", "from", "to", "q", "origin", "sort"]) {
        next.delete(k);
      }
      if (fixedEventType) next.set("event_type", fixedEventType);
      if (fixedResourceType) next.set("resource_type", fixedResourceType);
      next.set("limit", String(defaultLimit));
      next.set("sort", "desc");
      return next;
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
