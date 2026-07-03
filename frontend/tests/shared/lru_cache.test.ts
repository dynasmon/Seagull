import { describe, expect, it } from "vitest";

import { LruCache } from "@/shared/lib/lruCache";

describe("LruCache", () => {
  it("rejects invalid capacities", () => {
    expect(() => new LruCache<string, number>(0)).toThrow();
    expect(() => new LruCache<string, number>(1.5)).toThrow();
    expect(() => new LruCache<string, number>(Number.NaN)).toThrow();
  });

  it("stores and retrieves entries", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);

    expect(cache.get("a")).toBe(1);
    expect(cache.get("missing")).toBeUndefined();
    expect(cache.size).toBe(1);
  });

  it("evicts the least recently used entry when over capacity", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);

    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBe(2);
    expect(cache.get("c")).toBe(3);
    expect(cache.size).toBe(2);
  });

  it("treats get as a use for recency", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.get("a");
    cache.set("c", 3);

    expect(cache.get("a")).toBe(1);
    expect(cache.get("b")).toBeUndefined();
  });

  it("treats set of an existing key as a use for recency", () => {
    const cache = new LruCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("a", 10);
    cache.set("c", 3);

    expect(cache.get("a")).toBe(10);
    expect(cache.get("b")).toBeUndefined();
    expect(cache.size).toBe(2);
  });

  it("supports delete and clear", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);

    expect(cache.delete("a")).toBe(true);
    expect(cache.delete("a")).toBe(false);
    expect(cache.get("a")).toBeUndefined();

    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get("b")).toBeUndefined();
  });

  it("iterates keys from least to most recently used", () => {
    const cache = new LruCache<string, number>(3);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    cache.get("a");

    expect(Array.from(cache.keys())).toEqual(["b", "c", "a"]);
  });

  it("holds undefined-like values without corrupting recency", () => {
    const cache = new LruCache<string, number | undefined>(2);
    cache.set("a", undefined);
    cache.set("b", 2);

    expect(cache.has("a")).toBe(true);
    expect(cache.get("a")).toBeUndefined();
    cache.set("c", 3);
    expect(cache.has("a")).toBe(true);
    expect(cache.has("b")).toBe(false);
  });
});
