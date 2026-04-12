import { describe, expect, it } from "vitest";

import { sanitizeDataTableSort, sanitizeDataTableState } from "@/shared/lib/dataTablePreferences";

describe("data table preference sanitizers", () => {
  it("sanitizes valid sort payloads", () => {
    expect(sanitizeDataTableSort({ key: "created_at", direction: "desc" })).toEqual({
      key: "created_at",
      direction: "desc",
    });
  });

  it("rejects invalid sort payloads", () => {
    expect(sanitizeDataTableSort({ key: "", direction: "desc" })).toBeNull();
    expect(sanitizeDataTableSort({ key: "created_at", direction: "invalid" })).toBeNull();
    expect(sanitizeDataTableSort(null)).toBeNull();
  });

  it("clamps page size and falls back for invalid persisted shape", () => {
    const state = sanitizeDataTableState(
      {
        page_size: 9999,
        compact: "yes",
        sort: { key: "created_at", direction: "desc" },
      },
      {
        minPageSize: 10,
        maxPageSize: 500,
        fallbackPageSize: 50,
        fallbackCompact: false,
        fallbackSort: { key: "created_at", direction: "asc" },
      }
    );

    expect(state.page_size).toBe(500);
    expect(state.compact).toBe(false);
    expect(state.sort).toEqual({ key: "created_at", direction: "desc" });
  });
});

