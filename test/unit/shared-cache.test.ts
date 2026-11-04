import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { SharedJwksCache } from "../../src/cache/shared-cache.js";
import { configureHttp, resetHttpConfig } from "../../src/http/index.js";

beforeEach(() => {
  configureHttp({
    transport: async (input) => {
      const url = String(input);
      const kid = url.slice(-2);
      return new Response(
        JSON.stringify({
          keys: [{ kty: "RSA", kid, alg: "RS256", n: "n", e: "AQAB", use: "sig" }],
        }),
        { status: 200 },
      );
    },
  });
});

afterEach(() => {
  resetHttpConfig();
});

describe("SharedJwksCache", () => {
  it("isolates keys between tenants", async () => {
    const cache = new SharedJwksCache({ maxEntries: 100, perTenantMaxEntries: 50 });
    await cache.getKeys("tenant-a", "https://issuer/x", "https://issuer/x");
    await cache.getKeys("tenant-b", "https://issuer/x", "https://issuer/x");
    expect(cache.size()).toBe(2);
    expect(cache.has("tenant-a", "https://issuer/x")).toBe(true);
    expect(cache.has("tenant-b", "https://issuer/x")).toBe(true);
    expect(cache.stats().tenantCount).toBe(2);
  });

  it("enforces aggregate capacity by evicting LRU tenant", async () => {
    const cache = new SharedJwksCache({ maxEntries: 2, perTenantMaxEntries: 50 });
    await cache.getKeys("tenant-1", "https://issuer/1", "https://issuer/1");
    await cache.getKeys("tenant-2", "https://issuer/2", "https://issuer/2");
    expect(cache.size()).toBe(2);
    await cache.getKeys("tenant-3", "https://issuer/3", "https://issuer/3");
    expect(cache.size()).toBeLessThanOrEqual(2);
    expect(cache.has("tenant-1", "https://issuer/1")).toBe(false);
  });

  it("bounds each tenant's cache independently", async () => {
    const cache = new SharedJwksCache({ maxEntries: 1000, perTenantMaxEntries: 2 });
    for (let i = 0; i < 5; i += 1) {
      await cache.getKeys("tenant-a", `https://issuer/${i}`, `https://issuer/${i}`);
    }
    expect(cache.size()).toBeLessThanOrEqual(2);
    expect(cache.stats().perTenant["tenant-a"].size).toBeLessThanOrEqual(2);
  });

  it("invalidate removes a single tenant entry", async () => {
    const cache = new SharedJwksCache({ maxEntries: 100, perTenantMaxEntries: 50 });
    await cache.getKeys("tenant-a", "https://issuer/x", "https://issuer/x");
    expect(cache.has("tenant-a", "https://issuer/x")).toBe(true);
    cache.invalidate("tenant-a", "https://issuer/x");
    expect(cache.has("tenant-a", "https://issuer/x")).toBe(false);
  });

  it("invalidateTenant removes all entries for a tenant", async () => {
    const cache = new SharedJwksCache({ maxEntries: 100, perTenantMaxEntries: 50 });
    await cache.getKeys("tenant-a", "https://issuer/x", "https://issuer/x");
    await cache.getKeys("tenant-a", "https://issuer/y", "https://issuer/y");
    cache.invalidateTenant("tenant-a");
    expect(cache.has("tenant-a", "https://issuer/x")).toBe(false);
    expect(cache.has("tenant-a", "https://issuer/y")).toBe(false);
  });

  it("clear removes everything", async () => {
    const cache = new SharedJwksCache({ maxEntries: 100, perTenantMaxEntries: 50 });
    await cache.getKeys("tenant-a", "https://issuer/x", "https://issuer/x");
    await cache.getKeys("tenant-b", "https://issuer/y", "https://issuer/y");
    cache.clear();
    expect(cache.size()).toBe(0);
    expect(cache.stats().tenantCount).toBe(0);
  });

  it("reports aggregate stats", async () => {
    const cache = new SharedJwksCache({ maxEntries: 10, perTenantMaxEntries: 5 });
    await cache.getKeys("tenant-a", "https://issuer/x", "https://issuer/x");
    const stats = cache.stats();
    expect(stats.size).toBe(1);
    expect(stats.tenantCount).toBe(1);
    expect(stats.maxEntries).toBe(10);
    expect(stats.perTenantMaxEntries).toBe(5);
    expect(typeof stats.hits).toBe("number");
    expect(typeof stats.misses).toBe("number");
  });
});
