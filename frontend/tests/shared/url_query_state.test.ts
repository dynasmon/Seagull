import { describe, expect, it } from "vitest";

import { resolveNextUrlSearchParams } from "@/shared/lib/urlQueryState";

type QueryModel = {
  q: string;
  page: number;
};

function parse(sp: URLSearchParams): QueryModel {
  return {
    q: String(sp.get("q") || ""),
    page: Number(sp.get("page") || 1),
  };
}

function serialize(model: QueryModel): URLSearchParams {
  const out = new URLSearchParams();
  if (model.q) out.set("q", model.q);
  if (model.page > 1) out.set("page", String(model.page));
  return out;
}

describe("resolveNextUrlSearchParams", () => {
  it("returns previous params instance when next query is identical", () => {
    const prev = new URLSearchParams("q=agent&page=2");
    const out = resolveNextUrlSearchParams(prev, { q: "agent", page: 2 }, parse, serialize);

    expect(out).toBe(prev);
    expect(out.toString()).toBe("q=agent&page=2");
  });

  it("uses updater callback with parsed previous state", () => {
    const prev = new URLSearchParams("q=vuln&page=3");
    const out = resolveNextUrlSearchParams(
      prev,
      (current) => ({ ...current, page: current.page + 1 }),
      parse,
      serialize
    );

    expect(out.toString()).toBe("q=vuln&page=4");
  });

  it("removes optional keys when updater clears their value", () => {
    const prev = new URLSearchParams("q=admin&page=1");
    const out = resolveNextUrlSearchParams(prev, { q: "", page: 1 }, parse, serialize);

    expect(out.toString()).toBe("");
  });
});

