import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { JwksCache } from "../../src/crypto/jwks.js";
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

describe("JwksCache", () => {
  it("bounds entries to maxEntries and evicts LRU", async () => {
    const cache = new JwksCache({ maxEntries: 2 });
    for (let i = 0; i < 5; i += 1) {
      await cache.getKeys(`https://issuer/${i}`, `https://issuer/${i}`);
    }
    expect(cache.size()).toBeLessThanOrEqual(2);
    expect(cache.stats().evictions).toBeGreaterThan(0);
  });

  it("tracks cache hits and misses", async () => {
    const cache = new JwksCache({ maxEntries: 10 });
    await cache.getKeys("https://issuer/a", "https://issuer/a");
    const before = cache.stats();
    await cache.getKeys("https://issuer/a", "https://issuer/a");
    const after = cache.stats();
    expect(after.hits).toBeGreaterThan(before.hits);
    expect(after.misses).toBeGreaterThanOrEqual(before.misses);
  });

  it("bounds unknown kid cooldown storage", async () => {
    const cache = new JwksCache({ maxEntries: 2, unknownKidCooldownMs: 1 });
    for (let i = 0; i < 5; i += 1) {
      await cache.refreshForUnknownKid(`https://issuer/${i}`, `https://issuer/${i}`);
    }
    expect(cache.stats().unknownKidCount).toBeLessThanOrEqual(2);
  });

  it("limits concurrent inflight requests", async () => {
    const cache = new JwksCache({ maxInflight: 2 });
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        cache.getKeys(`https://issuer/${i}`, `https://issuer/${i}`),
      ),
    );
    expect(results).toHaveLength(10);
    expect(cache.stats().inflight).toBe(0);
    expect(cache.size()).toBeLessThanOrEqual(cache.stats().maxEntries);
  });

  it("reports configured limits in stats", () => {
    const cache = new JwksCache({ maxInflight: 25, maxEntries: 7 });
    expect(cache.stats().maxInflight).toBe(25);
    expect(cache.stats().maxEntries).toBe(7);
  });

  it("returns stats shape", async () => {
    const cache = new JwksCache({ maxEntries: 5 });
    await cache.getKeys("https://issuer/a", "https://issuer/a");
    const stats = cache.stats();
    expect(typeof stats.size).toBe("number");
    expect(typeof stats.hits).toBe("number");
    expect(typeof stats.misses).toBe("number");
    expect(typeof stats.evictions).toBe("number");
    expect(typeof stats.expired).toBe("number");
    expect(typeof stats.unknownKidCount).toBe("number");
    expect(typeof stats.queued).toBe("number");
  });
});
