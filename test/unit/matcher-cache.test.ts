import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { MatcherCache } from "../../src/rbac/matcher-cache.js";

describe("MatcherCache", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("starts empty", () => {
    const cache = new MatcherCache();
    expect(cache.size).toBe(0);
    expect(cache.stats().size).toBe(0);
  });

  it("stores and retrieves compiled matchers", () => {
    const cache = new MatcherCache();
    const matcher = /^post\.read$/;
    cache.set("post.read", matcher);
    expect(cache.get("post.read")).toBe(matcher);
    expect(cache.has("post.read")).toBe(true);
    expect(cache.stats().hits).toBe(1);
  });

  it("returns undefined for missing keys", () => {
    const cache = new MatcherCache();
    expect(cache.get("missing")).toBeUndefined();
    expect(cache.stats().misses).toBe(1);
  });

  it("never exceeds maxEntries", () => {
    const cache = new MatcherCache({ maxEntries: 3 });
    cache.set("a", /^a$/);
    cache.set("b", /^b$/);
    cache.set("c", /^c$/);
    expect(cache.size).toBe(3);

    cache.set("d", /^d$/);
    expect(cache.size).toBe(3);
    expect(cache.get("a")).toBeUndefined(); // oldest evicted
    expect(cache.get("d")).toBeDefined();
    expect(cache.stats().evictions).toBe(1);
    expect(cache.stats().size).toBeLessThanOrEqual(3);
  });

  it("promotes recently used entries (LRU eviction)", () => {
    const cache = new MatcherCache({ maxEntries: 3 });
    cache.set("a", /^a$/);
    cache.set("b", /^b$/);
    cache.set("c", /^c$/);
    cache.get("a"); // promote "a"

    cache.set("d", /^d$/); // "b" is now oldest
    expect(cache.get("a")).toBeDefined();
    expect(cache.get("b")).toBeUndefined();
  });

  it("expires entries by TTL", () => {
    const cache = new MatcherCache({ maxEntries: 10, ttl: 100 });
    const matcher = /^x$/;
    cache.set("x", matcher);
    vi.advanceTimersByTime(100);
    expect(cache.get("x")).toBeUndefined();
    expect(cache.has("x")).toBe(false);
    expect(cache.stats().expired).toBe(1);
  });

  it("disables TTL when ttl is 0", () => {
    const cache = new MatcherCache({ maxEntries: 10, ttl: 0 });
    cache.set("x", /^x$/);
    vi.advanceTimersByTime(10_000);
    expect(cache.get("x")).toBeDefined();
  });

  it("tracks stats", () => {
    const cache = new MatcherCache({ maxEntries: 2 });
    cache.set("a", /^a$/);
    cache.get("a"); // hit
    cache.get("missing"); // miss
    cache.set("b", /^b$/);
    cache.set("c", /^c$/); // evicts "a"
    const stats = cache.stats();
    expect(stats.maxEntries).toBe(2);
    expect(stats.ttl).toBe(0);
    expect(stats.hits).toBe(1);
    expect(stats.misses).toBe(1);
    expect(stats.evictions).toBe(1);
    expect(stats.size).toBe(2);
  });

  it("clear removes all entries and resets size", () => {
    const cache = new MatcherCache();
    cache.set("a", /^a$/);
    cache.set("b", /^b$/);
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBeUndefined();
  });

  it("delete removes a single entry", () => {
    const cache = new MatcherCache();
    cache.set("a", /^a$/);
    cache.set("b", /^b$/);
    expect(cache.delete("a")).toBe(true);
    expect(cache.delete("missing")).toBe(false);
    expect(cache.size).toBe(1);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBeDefined();
  });

  it("stays bounded under 100,000 unique patterns", () => {
    const cache = new MatcherCache({ maxEntries: 50 });
    for (let i = 0; i < 100_000; i += 1) {
      cache.set(`perm.${i}`, new RegExp(`^perm\\.${i}$`));
    }
    expect(cache.size).toBeLessThanOrEqual(50);
    expect(cache.stats().evictions).toBeGreaterThan(0);
  });

  it("default maxEntries is 1024", () => {
    const cache = new MatcherCache();
    expect(cache.stats().maxEntries).toBe(1024);
  });
});
